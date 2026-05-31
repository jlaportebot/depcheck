"""Command-line interface for depcheck."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console

from depcheck import __version__
from depcheck.licenses import LicenseCategory
from depcheck.output import determine_exit_code, render_json, render_table
from depcheck.scanner import normalize_package_name, scan_project


@click.group()
@click.version_option(version=__version__, prog_name="depcheck")
def main() -> None:
    """depcheck — A dependency health checker for Python projects.

    Scan your project's dependencies for vulnerabilities, outdated packages,
    unmaintained libraries, yanked or removed packages, and license compliance.
    """
    pass


@main.command()
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
    help="Output results as JSON (useful for CI/CD pipelines).",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["vulnerable", "outdated", "unmaintained", "license", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if the specified condition is met.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster but less comprehensive).",
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
    help="Allowed license categories. Repeat for multiple. "
    "E.g., --allow-license permissive --allow-license public_domain",
)
@click.option(
    "--deny-license",
    "denied_licenses",
    multiple=True,
    help="Specific SPDX license IDs to deny. Repeat for multiple. "
    'E.g., --deny-license GPL-3.0 --deny-license AGPL-3.0',
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def scan(
    path: str,
    output_json: bool,
    fail_on: str | None,
    no_vuln_check: bool,
    check_licenses: bool,
    allowed_licenses: tuple[str, ...],
    denied_licenses: tuple[str, ...],
    quiet: bool,
) -> None:
    """Scan a Python project for dependency health issues.

    PATH is the project directory to scan (defaults to current directory).
    depcheck looks for requirements.txt, pyproject.toml, or Pipfile.
    """
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
            category_map[cat.lower()]
            for cat in allowed_licenses
            if cat.lower() in category_map
        ]

    denied_list: list[str] | None = None
    if denied_licenses:
        denied_list = list(denied_licenses)

    # Enable license check if any license options are specified
    should_check_licenses = check_licenses or bool(allowed_licenses) or bool(denied_licenses)

    # Run the scan
    result = scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=should_check_licenses,
        allowed_license_categories=allowed_categories,
        denied_licenses=denied_list,
    )

    # Render output
    if output_json:
        render_json(result, console=Console(quiet=False) if quiet else None)
    elif not quiet:
        render_table(result)

    # Determine exit code
    exit_code = determine_exit_code(result, fail_on)

    if exit_code != 0 and not quiet:
        if fail_on:
            console.print(f"[red]✗ Scan failed: --fail-on {fail_on} condition met[/red]")

    sys.exit(exit_code)


@main.command()
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
    help="Output the dependency tree as JSON.",
)
@click.option(
    "--max-depth",
    type=int,
    default=3,
    help="Maximum depth to resolve in the dependency tree (default: 3).",
)
@click.option(
    "--display-depth",
    type=int,
    default=None,
    help="Maximum depth to display (useful for large trees). Defaults to --max-depth.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster tree resolution).",
)
@click.option(
    "--no-highlight",
    is_flag=True,
    default=False,
    help="Disable color-coded health status highlighting in the tree.",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance info in the tree (at top-level only).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def tree(
    path: str,
    output_json: bool,
    max_depth: int,
    display_depth: int | None,
    no_vuln_check: bool,
    no_highlight: bool,
    check_licenses: bool,
    quiet: bool,
) -> None:
    """Display the dependency tree for a Python project.

    PATH is the project directory to scan (defaults to current directory).
    Resolves the full dependency tree by querying PyPI for each package's
    declared dependencies and displays it with health status indicators.

    Each package shows its version and health status:
    ✓ healthy ↑ outdated ! vulnerable ⚠ unmaintained ✗ yanked/removed

    Circular dependencies are detected and marked with ↻.
    """
    from depcheck.tree import render_tree, render_tree_json, resolve_dependency_tree

    console = Console(quiet=quiet)

    # Resolve the dependency tree
    result = resolve_dependency_tree(
        project_path=path,
        max_depth=max_depth,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    # Render output
    if output_json:
        render_tree_json(result, console=Console(quiet=False) if quiet else None)
    elif not quiet:
        effective_display_depth = display_depth if display_depth is not None else max_depth
        render_tree(
            result,
            max_depth=effective_display_depth,
            highlight_issues=not no_highlight,
            console=console,
        )

    # Exit with error if there are circular deps or all packages failed
    if result.circular_deps:
        sys.exit(1)


@main.command()
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
def diff(
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


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["cyclonedx", "spdx", "summary"], case_sensitive=False),
    default="cyclonedx",
    help="SBOM output format (default: cyclonedx).",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write SBOM to file instead of stdout.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster but less comprehensive).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance information in the SBOM.",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output raw JSON even for summary format (instead of Rich table).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def export(
    path: str,
    fmt: str,
    output_file: str | None,
    no_vuln_check: bool,
    check_licenses: bool,
    json_output: bool,
    quiet: bool,
) -> None:
    """Generate a Software Bill of Materials (SBOM) for a project.

    PATH is the project directory to scan (defaults to current directory).

    Supports CycloneDX (OWASP standard) and SPDX (Linux Foundation standard)
    formats for supply chain security compliance.

    Examples:

    \b
    depcheck export --format cyclonedx
    depcheck export --format spdx --output sbom.json
    depcheck export --format summary --json-output
    depcheck export --format cyclonedx --output bom.cdx.json
    """
    from depcheck.export import (
        generate_sbom,
        render_cyclonedx,
        render_spdx,
        render_summary_json,
        render_summary_table,
        write_sbom_to_file,
    )

    console = Console(quiet=quiet)

    fmt = fmt.lower()

    # Generate SBOM
    sbom = generate_sbom(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        include_licenses=check_licenses,
    )

    if sbom.errors and not sbom.components:
        for error in sbom.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Output to file
    if output_file:
        written = write_sbom_to_file(sbom, format=fmt, output_path=output_file)
        if not quiet:
            console.print(f"[green]SBOM written to {written}[/green]")
            console.print(
                f"[dim]{sbom.total} components exported in {fmt} format[/dim]"
            )
        sys.exit(0)

    # Output to stdout
    if fmt == "cyclonedx":
        content = render_cyclonedx(sbom)
        if quiet:
            clean_console = Console(
                quiet=False, force_terminal=False, no_color=True
            )
        else:
            clean_console = Console(
                force_terminal=False, no_color=True
            )
        clean_console.print(content)
    elif fmt == "spdx":
        content = render_spdx(sbom)
        if quiet:
            clean_console = Console(
                quiet=False, force_terminal=False, no_color=True
            )
        else:
            clean_console = Console(
                force_terminal=False, no_color=True
            )
        clean_console.print(content)
    elif fmt == "summary":
        if json_output:
            content = render_summary_json(sbom)
            clean_console = Console(
                quiet=False, force_terminal=False, no_color=True
            ) if quiet else Console(force_terminal=False, no_color=True)
            clean_console.print(content)
    elif not quiet:
        render_summary_table(sbom, console=console)


@main.command()
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
    help="Output compliance report as JSON.",
)
@click.option(
    "--allow-license",
    "allowed_licenses",
    multiple=True,
    type=click.Choice(
        ["permissive", "copyleft", "public_domain", "proprietary"],
        case_sensitive=False,
    ),
    help="Allowed license categories. Repeat for multiple. "
    "E.g., --allow-license permissive --allow-license public_domain",
)
@click.option(
    "--deny-license",
    "denied_licenses",
    multiple=True,
    help="Specific SPDX license IDs to deny. Repeat for multiple. "
    'E.g., --deny-license GPL-3.0 --deny-license AGPL-3.0',
)
@click.option(
    "--deny-copyleft",
    is_flag=True,
    default=False,
    help="Deny all copyleft licenses (GPL, LGPL, AGPL, MPL, etc.).",
)
@click.option(
    "--strict",
    is_flag=True,
    default=False,
    help="Deny unknown/uncategorized licenses (fail-closed policy).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster).",
)
@click.option(
    "--fail-on-violation",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any non-compliant licenses are found.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def license(
    path: str,
    output_json: bool,
    allowed_licenses: tuple[str, ...],
    denied_licenses: tuple[str, ...],
    deny_copyleft: bool,
    strict: bool,
    no_vuln_check: bool,
    fail_on_violation: bool,
    quiet: bool,
) -> None:
    """Check license compliance for project dependencies.

    Scans your project's dependencies and reports on their license
    status — identifying SPDX license IDs, categories, and any
    compliance violations against your policy.

    Examples:

    \b
        depcheck license
        depcheck license --allow-license permissive --allow-license public_domain
        depcheck license --deny-license GPL-3.0 --deny-license AGPL-3.0
        depcheck license --deny-copyleft
        depcheck license --strict --fail-on-violation
        depcheck license --json
    """
    from depcheck.licenses import (
        ComplianceReport,
        LicenseCategory,
        LicenseInfo,
        LicensePolicy,
        PackageComplianceEntry,
        render_compliance_json,
        render_compliance_table,
    )
    from depcheck.scanner import scan_project

    console = Console(quiet=quiet)

    # Build license policy
    allowed_categories: set[LicenseCategory] | None = None
    if allowed_licenses:
        category_map = {
            "permissive": LicenseCategory.PERMISSIVE,
            "copyleft": LicenseCategory.COPYLEFT,
            "public_domain": LicenseCategory.PUBLIC_DOMAIN,
            "proprietary": LicenseCategory.PROPRIETARY,
        }
        allowed_categories = {
            category_map[cat.lower()]
            for cat in allowed_licenses
            if cat.lower() in category_map
        }

    denied_ids: set[str] | None = None
    if denied_licenses:
        denied_ids = set(denied_licenses)

    denied_categories: set[LicenseCategory] | None = None
    if deny_copyleft:
        denied_categories = {LicenseCategory.COPYLEFT}

    policy = LicensePolicy(
        allowed_categories=allowed_categories,
        denied_ids=denied_ids,
        denied_categories=denied_categories,
        default_allow=not strict,
    )

    # Run scan with license checking enabled
    result = scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=True,
        allowed_license_categories=list(allowed_categories) if allowed_categories else None,
        denied_licenses=list(denied_ids) if denied_ids else None,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Build compliance report from scan results
    entries: list[PackageComplianceEntry] = []
    for pkg in result.packages:
        info = pkg.license_info
        if info is None:
            info = LicenseInfo(spdx_id="", raw_license="UNKNOWN")

        # Re-check against policy
        compliance = policy.check(info.spdx_id)
        info.is_compliant = compliance.is_compliant
        if not compliance.is_compliant:
            info.compliance_note = compliance.reason

        entry = PackageComplianceEntry(
            name=pkg.name,
            version=pkg.installed_version,
            license_info=info,
            is_compliant=compliance.is_compliant,
            denial_reason=compliance.reason if not compliance.is_compliant else "",
        )
        entries.append(entry)

    report = ComplianceReport(
        packages=entries,
        total=len(entries),
        compliant_count=sum(1 for e in entries if e.is_compliant),
        non_compliant_count=sum(1 for e in entries if not e.is_compliant),
        uncategorized_count=sum(
            1
            for e in entries
            if e.license_info.category == LicenseCategory.UNKNOWN
        ),
        policy=policy,
    )

    # Render output
    if output_json:
        render_compliance_json(report)
    elif not quiet:
        render_compliance_table(report, console=console)

        # Exit code
    if fail_on_violation and report.non_compliant_count > 0:
        sys.exit(1)


@main.command()
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
    help="Output outdated report as JSON.",
)
@click.option(
    "--show-commands",
    is_flag=True,
    default=False,
    help="Show pip upgrade commands grouped by risk level.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance info in the report.",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["major", "minor", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if outdated packages at the specified level exist.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def outdated(
    path: str,
    output_json: bool,
    show_commands: bool,
    no_vuln_check: bool,
    check_licenses: bool,
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Check for outdated dependencies with upgrade path analysis.

    Shows which dependencies have newer versions available, classified
    by upgrade severity (major/minor/patch) with risk assessment and
    changelog links.

    PATH is the project directory to check (defaults to current directory).

    Examples:

    \b
    depcheck outdated
    depcheck outdated --json
    depcheck outdated --show-commands
    depcheck outdated --fail-on major
    depcheck outdated /path/to/project
    """
    from depcheck.outdated import (
        build_outdated_report,
        render_outdated_json,
        render_outdated_table,
        render_upgrade_commands,
    )

    console = Console(quiet=quiet)

    # Run the scan (fast — no vuln check by default for outdated)
    result = scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Build outdated report from scan results
    outdated_report = build_outdated_report(result)

    # Render output
    if output_json:
        content = render_outdated_json(outdated_report)
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    elif not quiet:
        render_outdated_table(outdated_report, console=console)
        if show_commands:
            render_upgrade_commands(outdated_report, console=console)

    # Exit code based on fail-on
    if fail_on:
        level_order = {
            "any": 0,
            "major": 1,
            "minor": 2,
        }
        threshold = level_order.get(fail_on.lower(), 1)

        has_major = outdated_report.major_count > 0
        has_minor = outdated_report.minor_count > 0

        should_fail = False
        if threshold == 0:  # any
            should_fail = outdated_report.outdated_count > 0
        elif threshold == 1:  # major
            should_fail = has_major
        elif threshold == 2:  # minor
            should_fail = has_major or has_minor

        if should_fail:
            if not quiet:
                console.print(
                    f"[red]✗ Outdated dependencies found: --fail-on {fail_on} "
                    f"condition met[/red]"
                )
            sys.exit(1)


@main.command()
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
    help="Output audit report as JSON (useful for CI/CD pipelines).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster but less comprehensive).",
)
@click.option(
    "--no-license-check",
    is_flag=True,
    default=False,
    help="Skip license compliance checking.",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["critical", "high", "medium", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if a package meets the risk threshold.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def audit(
    path: str,
    output_json: bool,
    no_vuln_check: bool,
    no_license_check: bool,
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Run a comprehensive security audit on your dependencies.

    Performs deep vulnerability analysis with severity breakdowns,
    per-package risk scoring, and actionable remediation advice.

    PATH is the project directory to audit (defaults to current directory).

    Examples:

    \b
    depcheck audit
    depcheck audit --json
    depcheck audit --fail-on high
    depcheck audit --fail-on critical
    depcheck audit /path/to/project
    """
    from depcheck.audit import RiskLevel, render_audit_json, render_audit_table, run_audit

    console = Console(quiet=quiet)

    result = run_audit(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=not no_license_check,
    )

    if result.errors and not result.all_risks:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Render output
    if output_json:
        render_audit_json(result)
    elif not quiet:
        render_audit_table(result, console=console)

    # Exit code based on risk threshold
    if fail_on:
        threshold_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "any": RiskLevel.LOW,
        }
        threshold = threshold_map.get(fail_on.lower(), RiskLevel.CRITICAL)
        level_order = {
            RiskLevel.NONE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        if level_order.get(result.risk_level, 0) >= level_order.get(threshold, 4):
            if not quiet:
                console.print(
                    f"[red]✗ Audit failed: risk level {result.risk_level.value} "
                    f"meets or exceeds --fail-on {fail_on} threshold[/red]"
                )
            sys.exit(1)


@main.command()
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
def watch(
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
            category_map[cat.lower()]
            for cat in allowed_licenses
            if cat.lower() in category_map
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


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--output",
    "-o",
    "output_path",
    default=None,
    type=click.Path(),
    help="Output HTML file path (default: ./depcheck-graph.html).",
)
@click.option(
    "--max-depth",
    default=3,
    type=int,
    help="Maximum depth to resolve the dependency tree (default: 3).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster but less comprehensive).",
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
    help="Allowed license categories for graph color indicators.",
)
@click.option(
    "--deny-license",
    "denied_licenses",
    multiple=True,
    help="Specific SPDX license IDs to deny. Repeat for multiple.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def graph(
    path: str,
    output_path: str | None,
    max_depth: int,
    no_vuln_check: bool,
    check_licenses: bool,
    allowed_licenses: tuple[str, ...],
    denied_licenses: tuple[str, ...],
    quiet: bool,
) -> None:
    """Generate an interactive dependency graph as an HTML file.

    Produces a self-contained HTML file with a D3.js force-directed graph
    showing your project's dependency tree. Nodes are color-coded by health
    status: green (healthy), yellow (outdated), red (vulnerable), gray
    (unmaintained), orange (yanked). The graph supports zoom, pan, search,
    and click-to-inspect package details.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck graph
    depcheck graph /path/to/project -o deps.html
    depcheck graph --max-depth 5 --check-licenses
    depcheck graph --no-vuln-check --quiet
    """
    from depcheck.graph import write_graph_html
    from depcheck.licenses import LicenseCategory

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
            category_map[cat.lower()]
            for cat in allowed_licenses
            if cat.lower() in category_map
        ]

    denied_list: list[str] | None = None
    if denied_licenses:
        denied_list = list(denied_licenses)

    # Enable license check if any license options are specified
    should_check_licenses = check_licenses or bool(allowed_licenses) or bool(denied_licenses)

    if not quiet:
        console.print("[bold]Resolving dependency tree...[/bold]")

    output = write_graph_html(
        project_path=path,
        output_path=output_path,
        max_depth=max_depth,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=should_check_licenses,
        allowed_license_categories=allowed_categories,
        denied_licenses=denied_list,
    )

    if not quiet:
        console.print(f"[green]✓ Dependency graph written to {output}[/green]")
        console.print("  Open in a browser to explore the interactive visualization.")


@main.command(name="repomap")
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
    help="Output the dependency map as JSON.",
)
@click.option(
    "--tree",
    "output_tree",
    is_flag=True,
    default=False,
    help="Display the dependency map as a tree.",
)
@click.option(
    "--impact",
    "impact_package",
    default=None,
    help="Analyze the impact of removing a specific package.",
)
@click.option(
    "--resolve-depth",
    type=int,
    default=2,
    help="Maximum depth to resolve transitive dependencies (default: 2).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def repomap(
    path: str,
    output_json: bool,
    output_tree: bool,
    impact_package: str | None,
    resolve_depth: int,
    quiet: bool,
) -> None:
    """Map dependency relationships and analyze impact of changes.

    Builds a complete dependency map showing which packages depend on which
    others, identifies critical packages (most depended-upon), orphans
    (packages nothing depends on), and can analyze the impact of removing
    a specific package.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck repomap
    depcheck repomap --tree
    depcheck repomap --json
    depcheck repomap --impact requests
    depcheck repomap --resolve-depth 3
    """
    from depcheck.repomap import (
        build_repomap,
        render_impact_json,
        render_impact_table,
        render_repomap_json,
        render_repomap_table,
        render_repomap_tree,
    )

    console = Console(quiet=quiet)

    if not quiet:
        console.print("[bold]Building dependency map...[/bold]")

    repo_map = build_repomap(
        project_path=path,
        resolve_depth=resolve_depth,
    )

    if impact_package:
        impact = repo_map.impact_analysis(impact_package)
        if output_json:
            content = render_impact_json(impact)
            clean_console = Console(
                quiet=False, force_terminal=False, no_color=True
            ) if quiet else Console(force_terminal=False, no_color=True)
            clean_console.print(content)
        else:
            render_impact_table(impact, console=console)
        return

    if output_json:
        content = render_repomap_json(repo_map)
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    elif output_tree:
        render_repomap_tree(repo_map, console=console)
    else:
        render_repomap_table(repo_map, console=console)


@main.command(name="depsize")
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
    help="Output the size report as JSON.",
)
@click.option(
    "--chart",
    is_flag=True,
    default=False,
    help="Show a text bar chart of package sizes.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance info.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def depsize(
    path: str,
    output_json: bool,
    chart: bool,
    no_vuln_check: bool,
    check_licenses: bool,
    quiet: bool,
) -> None:
    """Analyze dependency download and install sizes.

    Shows the download size and estimated install size for each
    dependency, identifies large and bloated packages, and calculates
    the total dependency footprint. Uses PyPI package file metadata.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck depsize
    depcheck depsize --json
    depcheck depsize --chart
    depcheck depsize /path/to/project
    """
    from depcheck.depsize import (
        build_size_report,
        render_size_bar_chart,
        render_size_json,
        render_size_table,
    )

    console = Console(quiet=quiet)

    if not quiet:
        console.print("[bold]Analyzing dependency sizes...[/bold]")

    report = build_size_report(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if output_json:
        content = render_size_json(report)
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    elif chart:
        render_size_bar_chart(report, console=console)
    else:
        render_size_table(report, console=console)


@main.command()
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
    help="Output the conflict report as JSON.",
)
@click.option(
    "--resolve-depth",
    type=int,
    default=2,
    help="Maximum depth to resolve transitive dependencies (default: 2).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def conflicts(
    path: str,
    output_json: bool,
    resolve_depth: int,
    quiet: bool,
) -> None:
    """Detect version conflicts between dependencies.

    Analyzes the full dependency tree for version conflicts — cases where
    different packages require incompatible versions of the same dependency.
    Reports hard conflicts (no compatible version exists), soft conflicts
    (narrow compatible range), and warnings about potential issues.

    Also detects circular dependencies.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck conflicts
    depcheck conflicts --json
    depcheck conflicts --resolve-depth 3
    depcheck conflicts /path/to/project
    """
    from depcheck.conflicts import (
        build_conflict_report,
        render_conflict_json,
        render_conflict_table,
    )

    console = Console(quiet=quiet)

    if not quiet:
        console.print("[bold]Analyzing dependency conflicts...[/bold]")

    report = build_conflict_report(
        project_path=path,
        resolve_depth=resolve_depth,
    )

    if output_json:
        content = render_conflict_json(report)
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    else:
        render_conflict_table(report, console=console)

    # Exit with error if hard conflicts found
    if report.hard_conflict_count > 0:
        sys.exit(1)


@main.command()
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
    help="Output the pin report as JSON.",
)
@click.option(
    "--generate-constraints",
    "gen_constraints",
    is_flag=True,
    default=False,
    help="Generate a pip constraints file.",
)
@click.option(
    "--output",
    "-o",
    "output_file",
    default=None,
    type=click.Path(),
    help="Output file path (for --generate-constraints).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def pinpoint(
    path: str,
    output_json: bool,
    gen_constraints: bool,
    output_file: str | None,
    quiet: bool,
) -> None:
    """Analyze version pinning quality and recommend improvements.

    Checks how each dependency is version-pinned (exact, compatible, minimum,
    range, wildcard, or unpinned) and recommends improvements. Calculates a
    pinning health score and can generate a pip constraints file.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck pinpoint
    depcheck pinpoint --json
    depcheck pinpoint --generate-constraints -o constraints.txt
    depcheck pinpoint /path/to/project
    """
    from depcheck.pinpoint import (
        build_pin_report,
        generate_constraints_file,
        render_pin_json,
        render_pin_table,
    )

    console = Console(quiet=quiet)

    if not quiet:
        console.print("[bold]Analyzing version pinning...[/bold]")

    report = build_pin_report(project_path=path)

    if gen_constraints:
        constraints = generate_constraints_file(report)
        if output_file:
            from pathlib import Path as PPath

            PPath(output_file).write_text(constraints)
            if not quiet:
                console.print(
                    f"[green]✓ Constraints file written to {output_file}[/green]"
                )
        else:
            clean_console = Console(
                quiet=False, force_terminal=False, no_color=True
            ) if quiet else Console(force_terminal=False, no_color=True)
            clean_console.print(constraints)
        return

    if output_json:
        content = render_pin_json(report)
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    else:
        render_pin_table(report, console=console)


@main.command()
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
    help="Output the scorecard as JSON.",
)
@click.option(
    "--markdown",
    is_flag=True,
    default=False,
    help="Output the scorecard as Markdown (for CI/CD integration).",
)
@click.option(
    "--badge",
    is_flag=True,
    default=False,
    help="Generate a shields.io badge URL for the scorecard grade.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster but less comprehensive).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance checking in the scorecard.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def scorecard(
    path: str,
    output_json: bool,
    markdown: bool,
    badge: bool,
    no_vuln_check: bool,
    check_licenses: bool,
    quiet: bool,
) -> None:
    """Generate a comprehensive dependency health scorecard.

    Combines multiple analysis dimensions (security, freshness, pinning,
    licenses, size, maintenance) into an overall project health grade
    from A+ to F. Provides actionable improvement suggestions ranked
    by impact.

    PATH is the project directory to score (defaults to current directory).

    Examples:

    \b
    depcheck scorecard
    depcheck scorecard --json
    depcheck scorecard --markdown
    depcheck scorecard --badge
    depcheck scorecard --check-licenses
    """
    from depcheck.scorecard import (
        build_scorecard,
        generate_badge_url,
        generate_markdown_report,
        render_scorecard,
        render_scorecard_json,
    )

    console = Console(quiet=quiet)

    if not quiet:
        console.print("[bold]Building dependency health scorecard...[/bold]")

    result = build_scorecard(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if badge:
        url = generate_badge_url(result)
        if not quiet:
            console.print(f"[bold]Badge URL:[/bold] {url}")
            console.print(f"[dim]Markdown: ![Score]({url})[/dim]")
        else:
            print(url)
        return

    if markdown:
        md = generate_markdown_report(result)
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
        clean_console.print(md)
        return

    if output_json:
        content = render_scorecard_json(result)
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    else:
        render_scorecard(result, console=console)

    # Exit with error if grade is D or F
    if result.grade.value in ("D", "F"):
        sys.exit(1)


@main.command()
@click.argument("query", nargs=-1, required=True)
@click.option(
    "--limit",
    type=int,
    default=10,
    help="Maximum number of results to return (default: 10).",
)
@click.option(
    "--category",
    type=click.Choice(
        ["web", "data", "testing", "cli", "database", "security", "ml", "devtools"],
        case_sensitive=False,
    ),
    default=None,
    help="Search by well-known category instead of query.",
)
@click.option(
    "--license",
    "license_filter",
    type=click.Choice(
        ["permissive", "copyleft", "public_domain", "proprietary"],
        case_sensitive=False,
    ),
    default=None,
    help="Filter results by license category.",
)
@click.option(
    "--python",
    "python_version",
    default=None,
    help="Filter by Python version compatibility (e.g., '3.11').",
)
@click.option(
    "--min-score",
    type=float,
    default=0.0,
    help="Minimum health score to include (0-100).",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output search results as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def search(
    query: tuple[str, ...],
    limit: int,
    category: str | None,
    license_filter: str | None,
    python_version: str | None,
    min_score: float,
    output_json: bool,
    quiet: bool,
) -> None:
    """Search for packages on PyPI with health scoring.

    QUERY is the package name or keyword to search for.
    Shows health scores, license info, dependency counts, and
    maintenance status for each result.

    Examples:

    \b
    depcheck search requests
    depcheck search "http client"
    depcheck search --category web --limit 5
    depcheck search --license permissive --min-score 70 flask
    depcheck search --python 3.11 asyncio
    depcheck search --json pytest
    """
    from depcheck.search import (
        render_search_json,
        render_search_table,
        search_by_category,
        search_packages,
    )

    console = Console(quiet=quiet)
    query_str = " ".join(query)

    if category:
        results = search_by_category(
            category=category,
            limit=limit,
            min_score=min_score,
        )
    else:
        results = search_packages(
            query=query_str,
            limit=limit,
            license_filter=license_filter,
            python_version=python_version,
            min_score=min_score,
        )

    if results.errors and not results.results:
        for error in results.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(render_search_json(results))
    elif not quiet:
        render_search_table(results, console=console)

    if not results.results:
        sys.exit(1)


@main.command()
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
    help="Output size report as JSON.",
)
@click.option(
    "--compare",
    multiple=True,
    help="Compare sizes of specific packages (repeat for each). "
    "E.g., --compare flask --compare django.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def size(
    path: str,
    output_json: bool,
    compare: tuple[str, ...],
    quiet: bool,
) -> None:
    """Analyze dependency sizes and disk footprint.

    Shows download size, estimated install size, and size category
    for each dependency. Identifies the largest packages and suggests
    lighter alternatives where available.

    PATH is the project directory to analyze (defaults to current directory).

    Use --compare to compare sizes of specific packages instead of
    analyzing a project.

    Examples:

    \b
    depcheck size
    depcheck size --json
    depcheck size /path/to/project
    depcheck size --compare flask --compare django --compare fastapi
    """
    from depcheck.size import (
        analyze_project_sizes,
        compare_package_sizes,
        render_size_comparison,
        render_size_json,
        render_size_table,
    )

    console = Console(quiet=quiet)

    if compare:
        # Compare mode: compare specific packages
        packages = compare_package_sizes(list(compare))
        if output_json:
            clean_console = (
                Console(quiet=False, force_terminal=False, no_color=True)
                if quiet
                else Console(force_terminal=False, no_color=True)
            )
            clean_console.print(
                json.dumps(
                    [p.to_dict() for p in packages],
                    indent=2,
                )
            )
        elif not quiet:
            render_size_comparison(packages, console=console)
        return

    # Project analysis mode
    report = analyze_project_sizes(project_path=path)

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(render_size_json(report))
    elif not quiet:
        render_size_table(report, console=console)


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--max-packages",
    type=int,
    default=None,
    help="Maximum number of direct dependencies allowed.",
)
@click.option(
    "--max-download-kb",
    type=float,
    default=None,
    help="Maximum total download size in KB.",
)
@click.option(
    "--max-install-kb",
    type=float,
    default=None,
    help="Maximum total install size in KB.",
)
@click.option(
    "--max-single-package-kb",
    type=float,
    default=None,
    help="Maximum download size for a single package in KB.",
)
@click.option(
    "--allow-license",
    "allowed_licenses",
    multiple=True,
    type=click.Choice(
        ["permissive", "copyleft", "public_domain", "proprietary"],
        case_sensitive=False,
    ),
    help="Allowed license categories for budget compliance.",
)
@click.option(
    "--deny-package",
    "denied_packages",
    multiple=True,
    help="Package names to deny (repeat for each).",
)
@click.option(
    "--require-package",
    "required_packages",
    multiple=True,
    help="Package names that must be present (repeat for each).",
)
@click.option(
    "--init",
    "init_config",
    is_flag=True,
    default=False,
    help="Create a default depcheck.budget.json config file.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output budget report as JSON.",
)
@click.option(
    "--fail-on-violation",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any budget rules are violated.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def budget(
    path: str,
    max_packages: int | None,
    max_download_kb: float | None,
    max_install_kb: float | None,
    max_single_package_kb: float | None,
    allowed_licenses: tuple[str, ...],
    denied_packages: tuple[str, ...],
    required_packages: tuple[str, ...],
    init_config: bool,
    output_json: bool,
    fail_on_violation: bool,
    quiet: bool,
) -> None:
    """Check dependency budget compliance.

    Analyzes your project's dependencies against budget constraints
    (max count, max size, allowed licenses, denied/required packages).
    Useful in CI to prevent dependency bloat.

    Budget rules can be configured via CLI options or a
    depcheck.budget.json file in the project root.

    Examples:

    \b
    depcheck budget
    depcheck budget --max-packages 20
    depcheck budget --max-download-kb 100000 --fail-on-violation
    depcheck budget --allow-license permissive --deny-package requests
    depcheck budget --require-package pytest --require-package ruff
    depcheck budget --init
    depcheck budget --json
    """
    from depcheck.budget import (
        BudgetConfig,
        check_budget,
        init_budget_file,
        render_budget_json,
        render_budget_table,
    )

    console = Console(quiet=quiet)

    # Init mode: create default config file
    if init_config:
        filepath = init_budget_file(path)
        if not quiet:
            console.print(f"[green]✓ Budget config created at {filepath}[/green]")
        return

    # Build config from CLI options
    config = None
    has_cli_overrides = any([
        max_packages is not None,
        max_download_kb is not None,
        max_install_kb is not None,
        max_single_package_kb is not None,
        allowed_licenses,
        denied_packages,
        required_packages,
    ])

    if has_cli_overrides:
        config = BudgetConfig()
        if max_packages is not None:
            config.max_packages = max_packages
        if max_download_kb is not None:
            config.max_total_download_kb = max_download_kb
        if max_install_kb is not None:
            config.max_total_install_kb = max_install_kb
        if max_single_package_kb is not None:
            config.max_single_package_kb = max_single_package_kb
        if allowed_licenses:
            config.allowed_license_categories = set(allowed_licenses)
        if denied_packages:
            config.denied_packages = {
                normalize_package_name(p) for p in denied_packages
            }
        if required_packages:
            config.required_packages = {
                normalize_package_name(p) for p in required_packages
            }

    # Run budget check
    report = check_budget(project_path=path, config=config)

    if output_json:
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(render_budget_json(report))
    elif not quiet:
        render_budget_table(report, console=console)

    # Exit code
    if fail_on_violation and not report.is_compliant:
        if not quiet:
            console.print("[red]✗ Budget violations detected[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
