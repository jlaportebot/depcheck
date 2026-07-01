"""Command-line interface for depcheck."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console

from depcheck import __version__
from depcheck.licenses import LicenseCategory
from depcheck.output import determine_exit_code, render_json, render_table
from depcheck.scanner import scan_project


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
    "E.g., --deny-license GPL-3.0 --deny-license AGPL-3.0",
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
            category_map[cat.lower()] for cat in allowed_licenses if cat.lower() in category_map
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
            console.print(f"[dim]{sbom.total} components exported in {fmt} format[/dim]")
        sys.exit(0)

    # Output to stdout
    if fmt == "cyclonedx":
        content = render_cyclonedx(sbom)
        if quiet:
            clean_console = Console(quiet=False, force_terminal=False, no_color=True)
        else:
            clean_console = Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    elif fmt == "spdx":
        content = render_spdx(sbom)
        if quiet:
            clean_console = Console(quiet=False, force_terminal=False, no_color=True)
        else:
            clean_console = Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    elif fmt == "summary":
        if json_output:
            content = render_summary_json(sbom)
            clean_console = (
                Console(quiet=False, force_terminal=False, no_color=True)
                if quiet
                else Console(force_terminal=False, no_color=True)
            )
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
    "E.g., --deny-license GPL-3.0 --deny-license AGPL-3.0",
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
            category_map[cat.lower()] for cat in allowed_licenses if cat.lower() in category_map
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
            info = LicenseInfo(
                spdx_id="",
                raw_license="UNKNOWN",
                category=LicenseCategory.UNKNOWN,
                is_compliant=True,
                compliance_note="",
            )

        # Re-check against policy
        compliance = policy.check(info.spdx_id)

        # Convert models.LicenseInfo to licenses.LicenseInfo for PackageComplianceEntry
        license_info_for_entry = LicenseInfo(
            spdx_id=info.spdx_id,
            raw_license=info.raw_license,
            category=LicenseCategory(info.category)
            if isinstance(info.category, str)
            else info.category,
            is_compliant=compliance.is_compliant,
            compliance_note=compliance.reason if not compliance.is_compliant else "",
        )

        entry = PackageComplianceEntry(
            name=pkg.name,
            version=pkg.installed_version,
            license_info=license_info_for_entry,
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
            1 for e in entries if e.license_info.category == LicenseCategory.UNKNOWN
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
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
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
                    f"[red]✗ Outdated dependencies found: --fail-on {fail_on} condition met[/red]"
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


@main.command()
@click.argument(
    "target_package",
)
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
    help="Output the dependency chains as JSON.",
)
@click.option(
    "--max-depth",
    type=int,
    default=4,
    help="Maximum depth to resolve in the dependency graph (default: 4).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster graph resolution).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def why(
    target_package: str,
    path: str,
    output_json: bool,
    max_depth: int,
    no_vuln_check: bool,
    quiet: bool,
) -> None:
    """Trace why a package is in your dependency tree.

    Finds all dependency chains from your direct dependencies down to
    the target package, showing the exact path that pulls it in.
    Useful for understanding transitive dependencies, debugging bloat,
    or deciding if a deep dependency is worth the risk.

    TARGET_PACKAGE is the name of the package to trace.

    PATH is the project directory to scan (defaults to current directory).

    Examples:

    \b
    depcheck why requests
    depcheck why urllib3 .
    depcheck why setuptools /path/to/project
    depcheck why numpy --json
    depcheck why pillow --max-depth 6
    depcheck why certifi --no-vuln-check
    """
    from depcheck.why import render_why_json, render_why_table, resolve_why

    console = Console(quiet=quiet)

    result = resolve_why(
        project_path=path,
        target_package=target_package,
        max_depth=max_depth,
        check_vulnerabilities=not no_vuln_check,
    )

    if result.errors and not result.found:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_why_json(result, console=Console(quiet=False) if quiet else None)
    elif not quiet:
        render_why_table(result, console=console)

    # Exit with code 1 if package not found
    if not result.found:
        sys.exit(1)


@main.command(name="check")
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
    help="Output health report as JSON.",
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
    help="Include license compliance in the health check.",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["critical", "high", "medium", "low", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if overall grade meets or falls below threshold.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def check(
    path: str,
    output_json: bool,
    no_vuln_check: bool,
    check_licenses: bool,
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Run a comprehensive health check with overall score and grades.

    Combines vulnerability, freshness, license, maintenance, transitive
    depth, and outdated analysis into a single 0–100 health score with
    per-category letter grades (A–F).

    PATH is the project directory to check (defaults to current directory).

    Examples:

    \b
    depcheck check
    depcheck check --json
    depcheck check --fail-on high
    depcheck check /path/to/project
    """
    from depcheck.check import Grade, render_check_json, render_check_table, run_check

    console = Console(quiet=quiet)

    report = run_check(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if report.errors and not report.categories:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_check_json(report)
    elif not quiet:
        render_check_table(report, console=console)

    # Exit code based on grade threshold
    if fail_on:
        grade_order = {
            Grade.A: 0,
            Grade.B: 1,
            Grade.C: 2,
            Grade.D: 3,
            Grade.F: 4,
        }
        threshold_map = {
            "critical": Grade.F,
            "high": Grade.D,
            "medium": Grade.C,
            "low": Grade.B,
            "any": Grade.A,
        }
        threshold = threshold_map.get(fail_on.lower(), Grade.F)
        if grade_order.get(report.overall_grade, 4) >= grade_order.get(threshold, 4):
            if not quiet:
                console.print(
                    f"[red]✗ Health check failed: grade {report.overall_grade.value} "
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
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output lockfile analysis as JSON.",
)
@click.option(
    "--audit",
    "run_audit_flag",
    is_flag=True,
    default=False,
    help="Run pip-audit for vulnerability scanning (requires pip-audit installed).",
)
@click.option(
    "--diff",
    "diff_target",
    type=click.Path(exists=True),
    default=None,
    help="Compare lockfile against another lockfile to show diff.",
)
@click.option(
    "--freeze",
    is_flag=True,
    default=False,
    help="Generate a pip freeze output for the current environment.",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write freeze output to file (use with --freeze).",
)
@click.option(
    "--fail-on-unpinned",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any unpinned dependencies are found.",
)
@click.option(
    "--fail-on-drift",
    is_flag=True,
    default=False,
    help="Exit with code 1 if any version drift is detected.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def lockfile(
    path: str,
    output_json: bool,
    run_audit_flag: bool,
    diff_target: str | None,
    freeze: bool,
    output_file: str | None,
    fail_on_unpinned: bool,
    fail_on_drift: bool,
    quiet: bool,
) -> None:
    """Analyze lockfiles for unpinned deps, drift, and hash issues.

    Finds and analyzes all lockfile types in your project: requirements.txt,
    Pipfile.lock, and poetry.lock. Detects unpinned dependencies, version
    drift from manifests, missing hashes, and (optionally) runs pip-audit.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck lockfile
    depcheck lockfile --json
    depcheck lockfile --audit
    depcheck lockfile --freeze
    depcheck lockfile --freeze --output requirements.lock
    depcheck lockfile --diff requirements.old.txt
    depcheck lockfile --fail-on-unpinned
    """
    from pathlib import Path

    from depcheck.lockfile import (
        analyze_project_lockfiles,
        diff_lockfiles,
        find_lockfiles,
        generate_freeze,
        render_lockfile_diff_table,
        render_lockfile_json,
        render_lockfile_table,
        render_pip_audit_table,
        run_pip_audit,
    )

    console = Console(quiet=quiet)

    # Freeze mode
    if freeze:
        content = generate_freeze(project_path=path, output_path=output_file)
        if not output_file and not quiet:
            console.print(content)
        if output_file and not quiet:
            console.print(f"[green]Freeze written to {output_file}[/green]")
        return

    # Diff mode
    if diff_target:
        project = Path(path).resolve()
        lockfiles = find_lockfiles(project)
        if not lockfiles:
            console.print("[red]No lockfiles found in project[/red]")
            sys.exit(1)

        target_path = Path(diff_target).resolve()
        # Use the first lockfile found as the "old" side
        old_path = lockfiles[0]
        result = diff_lockfiles(old_path, target_path)
        if output_json:
            console.print(json.dumps(result.to_dict(), indent=2))
        elif not quiet:
            render_lockfile_diff_table(result, console=console)
        if result.has_changes and fail_on_drift:
            sys.exit(1)
        return

    # Normal analysis mode
    reports = analyze_project_lockfiles(project_path=path)

    if not reports:
        if not quiet:
            console.print("[yellow]No lockfiles found in project.[/yellow]")
            console.print(
                "[dim]Create a requirements.txt with pinned versions, or use --freeze to generate one.[/dim]"
            )
        sys.exit(0)

    if output_json:
        render_lockfile_json(reports)
    elif not quiet:
        render_lockfile_table(reports, console=console)

    # pip-audit integration
    if run_audit_flag:
        # Find the first requirements-style lockfile to audit
        req_path: Path | None = None
        for lf in find_lockfiles(Path(path).resolve()):
            if lf.name.endswith(".txt"):
                req_path = lf
                break

        audit_result = run_pip_audit(req_path)
        if not quiet:
            render_pip_audit_table(audit_result, console=console)

    # Exit codes
    for report in reports:
        if fail_on_unpinned and report.unpinned:
            if not quiet:
                console.print(f"[red]✗ Unpinned dependencies found in {report.path}[/red]")
            sys.exit(1)
        if fail_on_drift and report.drift:
            if not quiet:
                console.print(f"[red]✗ Version drift detected in {report.path}[/red]")
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
    type=click.Choice(
        ["plain", "markdown", "json", "ai"],
        case_sensitive=False,
    ),
    default="plain",
    help="Output format (default: plain). 'ai' is compact for LLM context windows.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster explanations).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance info in explanations.",
)
@click.option(
    "--filter",
    "filter_status",
    type=click.Choice(
        ["vulnerable", "outdated", "unmaintained", "at-risk", "all"],
        case_sensitive=False,
    ),
    default="all",
    help="Filter to only show packages with the specified status.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def explain(
    path: str,
    fmt: str,
    no_vuln_check: bool,
    check_licenses: bool,
    filter_status: str,
    quiet: bool,
) -> None:
    """Explain what each dependency does and its health status.

    Generates human-readable explanations for every dependency in
    your project, including what the package provides, its ecosystem
    role, alternatives, and actionable risk items.

    PATH is the project directory to explain (defaults to current directory).

    Examples:

    \b
    depcheck explain
    depcheck explain --format markdown
    depcheck explain --format json
    depcheck explain --format ai
    depcheck explain --filter at-risk
    depcheck explain --filter vulnerable
    depcheck explain --check-licenses
    """
    from depcheck.explain import (
        explain_project,
        render_explain_ai,
        render_explain_json,
        render_explain_markdown,
        render_explain_plain,
    )
    from depcheck.models import HealthStatus

    console = Console(quiet=quiet)

    report = explain_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Apply filter
    if filter_status != "all":
        if filter_status == "at-risk":
            report.packages = [
                p for p in report.packages if p.is_vulnerable or p.is_outdated or p.is_unmaintained
            ]
        else:
            status_map = {
                "vulnerable": HealthStatus.VULNERABLE,
                "outdated": HealthStatus.OUTDATED,
                "unmaintained": HealthStatus.UNMAINTAINED,
            }
            target_status = status_map.get(filter_status)
            if target_status:
                report.packages = [p for p in report.packages if p.status == target_status]

    fmt_lower = fmt.lower()
    if fmt_lower == "json":
        render_explain_json(report)
    elif fmt_lower == "markdown":
        render_explain_markdown(report, console=console)
    elif fmt_lower == "ai":
        render_explain_ai(report)
    else:
        render_explain_plain(report, console=console)


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
    "--top-n",
    type=int,
    default=20,
    help="Number of largest packages to highlight (default: 20).",
)
@click.option(
    "--no-top-files",
    is_flag=True,
    default=False,
    help="Don't show largest files per package.",
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
    top_n: int,
    no_top_files: bool,
    quiet: bool,
) -> None:
    """Analyze the installed size of each dependency.

    Measures the disk footprint of every dependency in your project by
    inspecting the local site-packages directory. Reports total bytes,
    file counts, and identifies the largest packages and files.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck size
    depcheck size --json
    depcheck size --top-n 10
    depcheck size --no-top-files
    depcheck size /path/to/project
    """
    from depcheck.size import analyze_sizes, render_size_json, render_size_table

    console = Console(quiet=quiet)

    report = analyze_sizes(
        project_path=path,
        top_n=top_n,
        include_top_files=not no_top_files,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_size_json(report)
    elif not quiet:
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
    help="Output suggestions as JSON.",
)
@click.option(
    "--policy",
    type=click.Choice(["relaxed", "standard", "strict"]),
    default="standard",
    help="Health policy threshold for recommendations (default: standard).",
)
@click.option(
    "--min-score",
    type=int,
    default=0,
    help="Minimum recommendation score (0-100) to include.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def suggest(
    path: str,
    output_json: bool,
    policy: str,
    min_score: int,
    quiet: bool,
) -> None:
    """Suggest healthier alternative dependencies.

    Analyzes your project dependencies and recommends alternatives based on
    maintenance health, popularity, and compatibility.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck suggest
    depcheck suggest /path/to/project --policy strict
    depcheck suggest . --json > suggestions.json
    depcheck suggest . --min-score 60
    """
    from depcheck.suggest import render_suggest_json, render_suggest_table, suggest_alternatives

    console = Console(quiet=quiet)
    result = suggest_alternatives(
        project_path=path,
    )

    if output_json:
        console = Console(quiet=False, force_terminal=False, no_color=True)
        console.print(render_suggest_json(result))
    elif not quiet:
        render_suggest_table(result, console=console)

    if result.errors:
        sys.exit(2)


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
    help="Output history report as JSON.",
)
@click.option(
    "--max-versions",
    type=int,
    default=20,
    help="Maximum historical versions to retrieve per package (default: 20).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def history(
    path: str,
    output_json: bool,
    max_versions: int,
    quiet: bool,
) -> None:
    """Analyze the release history and maintenance trends of dependencies.

    Shows version timelines, release cadence, maintenance trends
    (accelerating, steady, slowing, abandoned), and version age for
    each dependency.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck history
    depcheck history --json
    depcheck history --max-versions 10
    depcheck history /path/to/project
    """
    from depcheck.history import analyze_history, render_history_json, render_history_table

    console = Console(quiet=quiet)

    report = analyze_history(
        project_path=path,
        max_versions=max_versions,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_history_json(report)
    elif not quiet:
        render_history_table(report, console=console)


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
    help="Output bundle report as JSON.",
)
@click.option(
    "--with",
    "extra_commands",
    multiple=True,
    type=click.Choice(
        ["check", "audit", "outdated", "license", "size", "history"],
        case_sensitive=False,
    ),
    help="Commands to include in the bundle. Repeat for multiple. Default: check, audit, outdated.",
)
@click.option(
    "--all",
    "run_all",
    is_flag=True,
    default=False,
    help="Run all available commands (check, audit, outdated, license, size, history).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def bundle(
    path: str,
    output_json: bool,
    extra_commands: tuple[str, ...],
    run_all: bool,
    quiet: bool,
) -> None:
    """Run multiple depcheck commands in a single pass.

    Executes a configurable bundle of analyses (check, audit, outdated,
    license, size, history) and produces a combined report. Ideal for
    CI pipelines and nightly audits.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck bundle
    depcheck bundle --all
    depcheck bundle --with audit --with license --with size
    depcheck bundle --json
    depcheck bundle --all --json
    """
    from depcheck.bundle import BundleCommand, render_bundle_json, render_bundle_table, run_bundle

    console = Console(quiet=quiet)

    # Build command list
    if run_all:
        commands = list(BundleCommand)
    elif extra_commands:
        name_to_cmd = {cmd.value: cmd for cmd in BundleCommand}
        commands = [name_to_cmd[cmd] for cmd in extra_commands if cmd in name_to_cmd]
    else:
        commands = None  # Use default bundle

    report = run_bundle(project_path=path, commands=commands)

    if report.errors and not report.results:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_bundle_json(report)
    elif not quiet:
        render_bundle_table(report, console=console)

    if not report.overall_success:
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
    help="Output diagnostic report as JSON.",
)
@click.option(
    "--fail-on",
    type=click.Choice(
        ["critical", "warning", "any"],
        case_sensitive=False,
    ),
    default=None,
    help="Exit with code 1 if findings meet the severity threshold.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def doctor(
    path: str,
    output_json: bool,
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Diagnose dependency configuration and environment issues.

    Runs a comprehensive diagnostic on your project's dependency setup,
    checking for unpinned versions, missing lockfiles, venv issues,
    Python compatibility, import consistency, and formatting problems.

    PATH is the project directory to diagnose (defaults to current directory).

    Examples:

    \b
    depcheck doctor
    depcheck doctor --json
    depcheck doctor --fail-on critical
    depcheck doctor --fail-on warning
    depcheck doctor /path/to/project
    """
    from depcheck.doctor import Severity, render_doctor_json, render_doctor_table, run_doctor

    console = Console(quiet=quiet)

    report = run_doctor(project_path=path)

    if report.errors and not report.findings:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_doctor_json(report)
    elif not quiet:
        render_doctor_table(report, console=console)

    # Exit code based on fail-on
    if fail_on:
        severity_threshold = {
            "critical": Severity.CRITICAL,
            "warning": Severity.WARNING,
            "any": Severity.INFO,
        }
        threshold = severity_threshold.get(fail_on.lower(), Severity.CRITICAL)

        level_order = {
            Severity.INFO: 0,
            Severity.WARNING: 1,
            Severity.CRITICAL: 2,
        }
        _ = level_order.get(threshold, 2)

        if fail_on.lower() == "critical" and report.critical_count > 0:
            if not quiet:
                console.print(
                    f"[red]✗ Doctor found {report.critical_count} critical issue(s)[/red]"
                )
            sys.exit(1)
        elif fail_on.lower() == "warning" and (
            report.critical_count > 0 or report.warning_count > 0
        ):
            if not quiet:
                console.print(
                    f"[red]✗ Doctor found {report.critical_count} critical "
                    f"and {report.warning_count} warning(s)[/red]"
                )
            sys.exit(1)
        elif fail_on.lower() == "any" and not report.is_healthy:
            if not quiet:
                console.print(
                    f"[red]✗ Doctor found {report.critical_count} critical, "
                    f"{report.warning_count} warnings, "
                    f"{report.info_count} info[/red]"
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
    help="Output budget report as JSON.",
)
@click.option(
    "--per-dep-limit",
    type=int,
    default=None,
    help="Maximum allowed dependencies per single dependency.",
)
@click.option(
    "--transitive-limit",
    type=int,
    default=None,
    help="Maximum allowed total transitive dependencies.",
)
@click.option(
    "--depth-limit",
    type=int,
    default=None,
    help="Maximum allowed dependency depth.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def budget(
    path: str,
    output_json: bool,
    per_dep_limit: int | None,
    transitive_limit: int | None,
    depth_limit: int | None,
    quiet: bool,
) -> None:
    """Analyse dependency budget and cost metrics.

    Shows per-dependency transitive counts, depth, and estimated risk
    for every direct dependency. Use limits to fail CI when budgets
    are exceeded.

    PATH is the project directory to analyse (defaults to current directory).

    Examples:

    \b
    depcheck budget
    depcheck budget --per-dep-limit 20
    depcheck budget --transitive-limit 200 --depth-limit 5
    depcheck budget --json
    """
    from depcheck.budget import (
        BudgetConfig,
        check_budget,
        render_budget_json,
        render_budget_table,
    )

    console = Console(quiet=quiet)

    config = BudgetConfig(
        total=transitive_limit,
        direct=per_dep_limit,
        transitive=transitive_limit,
        dev=None,
        optional=None,
    )

    report = check_budget(project_path=path, config=config)

    if report.errors and not report.categories:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_budget_json(report)
    elif not quiet:
        render_budget_table(report, console=console)

    if not report.is_within_budget:
        if not quiet:
            console.print(
                f"[red]✗ Budget exceeded: {len(report.over_budget_categories)} "
                f"limit(s) violated[/red]"
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
    help="Output risk report as JSON.",
)
@click.option(
    "--severity-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
    help="Minimum severity to include in output.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def risks(
    path: str,
    output_json: bool,
    severity_threshold: str,
    quiet: bool,
) -> None:
    """Assess multi-dimensional risk scores for dependencies.

    Evaluates each dependency across vulnerability, maintenance, age,
    popularity, and license risk dimensions. Produces a composite
    risk score and remediation priority list.

    PATH is the project directory to analyse (defaults to current directory).

    Examples:

    \b
    depcheck risks
    depcheck risks --severity-threshold high
    depcheck risks --json
    """
    from depcheck.risks import (
        RiskSeverity,
        assess_risks,
        render_risks_json,
        render_risks_table,
    )

    console = Console(quiet=quiet)

    severity_map = {
        "low": RiskSeverity.LOW,
        "medium": RiskSeverity.MEDIUM,
        "high": RiskSeverity.HIGH,
        "critical": RiskSeverity.CRITICAL,
    }
    threshold = severity_map.get(severity_threshold, RiskSeverity.MEDIUM)

    report = assess_risks(project_path=path, min_severity=threshold)

    if report.errors and not report.entries:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_risks_json(report)
    elif not quiet:
        render_risks_table(report, console=console)

    if report.critical_count > 0:
        if not quiet:
            console.print(f"[red]✗ {report.critical_count} critical-risk dependencies found[/red]")
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
    help="Output advisory report as JSON.",
)
@click.option(
    "--source",
    type=click.Choice(["osv", "pypa", "github", "all"]),
    default="all",
    help="Advisory source to query.",
)
@click.option(
    "--severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default=None,
    help="Filter advisories by minimum severity.",
)
@click.option(
    "--patched-only",
    is_flag=True,
    default=False,
    help="Only show advisories with a known fix.",
)
@click.option(
    "--unpatched-only",
    is_flag=True,
    default=False,
    help="Only show advisories without a known fix.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def advisories(
    path: str,
    output_json: bool,
    source: str,
    severity: str | None,
    patched_only: bool,
    unpatched_only: bool,
    quiet: bool,
) -> None:
    """Check security advisories for project dependencies.

    Queries multiple advisory databases (OSV, PyPA, GitHub) for
    known vulnerabilities affecting your dependencies. Shows
    severity, affected versions, and available fixes.

    PATH is the project directory to check (defaults to current directory).

    Examples:

    \b
    depcheck advisories
    depcheck advisories --source osv
    depcheck advisories --severity high
    depcheck advisories --unpatched-only
    depcheck advisories --json
    """
    from depcheck.advisories import (
        AdvisorySource,
        render_advisories_json,
        render_advisories_table,
        run_advisories,
    )

    console = Console(quiet=quiet)

    source_map = {
        "osv": [AdvisorySource.OSV],
        "pypa": [AdvisorySource.PYPA],
        "github": [AdvisorySource.GITHUB],
        "all": [AdvisorySource.OSV, AdvisorySource.PYPA, AdvisorySource.GITHUB],
    }
    sources = source_map.get(source, source_map["all"])

    report = run_advisories(
        project_path=path,
        check_vulnerabilities=True,
        sources=sources,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Apply filters if specified
    if severity or patched_only or unpatched_only:
        for pkg_summary in report.packages:
            filtered = pkg_summary.advisories
            if severity:
                filtered = [a for a in filtered if a.severity.upper() >= severity.upper()]
            if patched_only:
                filtered = [a for a in filtered if a.is_patchable]
            if unpatched_only:
                filtered = [a for a in filtered if not a.is_patchable]
            pkg_summary.advisories = filtered
            pkg_summary.total_advisories = len(filtered)

    if output_json:
        render_advisories_json(report)
    elif not quiet:
        render_advisories_table(report, console=console)

    if report.total_critical > 0:
        if not quiet:
            console.print(f"[red]✗ {report.total_critical} critical advisories found[/red]")
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
    type=click.Choice(["ascii", "dot", "mermaid", "json"]),
    default="ascii",
    help="Output format for the dependency graph.",
)
@click.option(
    "--max-depth",
    type=int,
    default=4,
    help="Maximum depth for transitive dependency resolution.",
)
@click.option(
    "--subgraph",
    default=None,
    help="Extract subgraph rooted at this package name.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def graph(
    path: str,
    fmt: str,
    max_depth: int,
    subgraph: str | None,
    quiet: bool,
) -> None:
    """Visualise the dependency graph.

    Builds and analyses the full dependency graph, detecting cycles,
    diamond dependencies, and computing centrality metrics. Supports
    multiple output formats for integration with visualisation tools.

    PATH is the project directory to analyse (defaults to current directory).

    Examples:

    \b
    depcheck graph
    depcheck graph --format dot > deps.dot
    depcheck graph --format mermaid > deps.mmd
    depcheck graph --subgraph requests
    depcheck graph --max-depth 2 --format json
    """
    from depcheck.graph import (
        GraphFormat,
        build_dependency_graph,
        extract_subgraph,
        render_graph,
    )

    console = Console(quiet=quiet)

    full_graph = build_dependency_graph(
        project_path=path,
        max_depth=max_depth,
    )

    if full_graph.errors and not full_graph.nodes:
        for error in full_graph.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Extract subgraph if requested
    target_graph = full_graph
    if subgraph:
        target_graph = extract_subgraph(full_graph, root=subgraph, max_depth=max_depth)
        if target_graph.errors:
            for error in target_graph.errors:
                console.print(f"[red]Error:[/red] {error}")
            sys.exit(2)

    fmt_map = {
        "ascii": GraphFormat.ASCII,
        "dot": GraphFormat.DOT,
        "mermaid": GraphFormat.MERMAID,
        "json": GraphFormat.JSON,
    }
    graph_fmt = fmt_map.get(fmt, GraphFormat.ASCII)

    if not quiet:
        render_graph(target_graph, fmt=graph_fmt, console=console)

    if len(full_graph.cycles) > 0:
        if not quiet and graph_fmt == GraphFormat.JSON:
            pass  # Cycles shown in JSON output
        elif not quiet:
            console.print(
                f"\n[yellow]⚠ {len(full_graph.cycles)} dependency cycle(s) detected[/yellow]"
            )


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
    help="Output policy report as JSON.",
)
@click.option(
    "--no-vulns",
    is_flag=True,
    default=False,
    help="Skip vulnerability checks during policy evaluation.",
)
@click.option(
    "--no-licenses",
    is_flag=True,
    default=False,
    help="Skip license checks during policy evaluation.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def policy(
    path: str,
    output_json: bool,
    no_vulns: bool,
    no_licenses: bool,
    quiet: bool,
) -> None:
    """Evaluate dependency policies and check compliance.

    Loads policy rules from [tool.depcheck.policy] in pyproject.toml
    and evaluates them against your project's dependencies. Reports
    violations by severity (error, warning, info) with remediation
    guidance. Exits with code 1 if any error-severity rules are
    violated.

    PATH is the project directory to check (defaults to current directory).

    Examples:

    \b
    depcheck policy
    depcheck policy --json
    depcheck policy --no-vulns
    """
    from depcheck.policy import (
        evaluate_policy,
        render_policy_json,
        render_policy_table,
    )

    console = Console(quiet=quiet)

    report = evaluate_policy(
        project_path=path,
        check_vulnerabilities=not no_vulns,
        check_licenses=not no_licenses,
    )

    if report.errors and not report.violations and report.total_packages == 0:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_policy_json(report)
    elif not quiet:
        render_policy_table(report, console=console)

    if not report.is_compliant:
        if not quiet:
            console.print(
                f"[red]✗ Policy non-compliant: {report.error_count} "
                f"error(s), compliance score {report.compliance_score}%[/red]"
            )
        sys.exit(1)


# ── New commands: update, isolate, sizescore, depdrift, compat ─────────────────


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--pinned",
    is_flag=True,
    default=False,
    help="Treat all exact-version deps as pinned (affects strategy).",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def update(
    path: str,
    pinned: bool,
    no_vuln_check: bool,
    quiet: bool,
) -> None:
    """Generate a safe, prioritized update plan for dependencies.

    Analyzes your project's dependencies and produces a step-by-step
    update plan ordered by priority (security fixes first, then
    major → minor → patch). Each step includes pip commands, risk
    assessment, and strategy recommendations.

    PATH is the project directory (defaults to current directory).

    Examples:

    \b
    depcheck update
    depcheck update --json
    depcheck update --pinned
    depcheck update /path/to/project
    """
    from depcheck.update import (
        build_update_plan,
        render_update_plan_json,
        render_update_plan_table,
    )

    console = Console(quiet=quiet)

    result = scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Determine pinned packages
    pinned_set: set[str] | None = None
    if pinned:
        pinned_set = {
            pkg.name
            for pkg in result.packages
            if pkg.installed_version and pkg.installed_version != "unknown"
        }

    plan = build_update_plan(result, pinned_packages=pinned_set)

    output_json = False  # update command doesn't have --json flag
    if output_json:
        content = render_update_plan_json(plan)
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(content)
    elif not quiet:
        render_update_plan_table(plan, console=console)


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
    help="Output isolation report as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def isolate(
    path: str,
    output_json: bool,
    quiet: bool,
) -> None:
    """Analyze which dependencies can be safely removed.

    Scans your project's source code for import statements and
    cross-references them with declared dependencies to find packages
    that are unused, transitive-only, or safely removable.

    PATH is the project directory (defaults to current directory).

    Examples:

    \b
    depcheck isolate
    depcheck isolate --json
    depcheck isolate /path/to/project
    """
    from pathlib import Path

    from depcheck.isolate import (
        analyze_isolation,
        render_isolation_json,
        render_isolation_table,
    )

    console = Console(quiet=quiet)

    report = analyze_isolation(project_path=Path(path))

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        content = render_isolation_json(report)
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(content)
    elif not quiet:
        render_isolation_table(report, console=console)


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
    help="Output size score report as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def sizescore(
    path: str,
    output_json: bool,
    quiet: bool,
) -> None:
    """Analyze dependency sizes and bloat.

    Checks download/install sizes of your dependencies, detects
    size trends (bloat vs. lean), suggests lighter alternatives
    for heavy packages, and computes a size efficiency score.

    PATH is the project directory (defaults to current directory).

    Examples:

    \b
    depcheck sizescore
    depcheck sizescore --json
    depcheck sizescore /path/to/project
    """
    from depcheck.sizescore import (
        build_size_report,
        render_size_json,
        render_size_table,
    )

    console = Console(quiet=quiet)

    report = build_size_report(project_path=path)

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        content = render_size_json(report)
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(content)
    elif not quiet:
        render_size_table(report, console=console)


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--from-commit",
    "from_commit",
    default=None,
    help="Starting git commit (uses oldest if not set).",
)
@click.option(
    "--to-commit",
    "to_commit",
    default=None,
    help="Ending git commit (uses HEAD if not set).",
)
@click.option(
    "--max-commits",
    type=int,
    default=20,
    help="Max commits to scan for dependency changes (default: 20).",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output drift report as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def depdrift(
    path: str,
    from_commit: str | None,
    to_commit: str | None,
    max_commits: int,
    output_json: bool,
    quiet: bool,
) -> None:
    """Track dependency drift over time via git history.

    Compares your project's dependency files across git commits to
    detect version drift, package additions/removals, and pin erosion.
    Computes drift velocity and identifies high-drift packages.

    PATH is the project directory (defaults to current directory).
    Must be a git repository.

    Examples:

    \b
    depcheck depdrift
    depcheck depdrift --json
    depcheck depdrift --from-commit abc123 --to-commit def456
    depcheck depdrift --max-commits 50
    """
    from depcheck.depdrift import (
        build_drift_report,
        render_drift_json,
        render_drift_table,
    )

    console = Console(quiet=quiet)

    report = build_drift_report(
        project_path=path,
        from_commit=from_commit,
        to_commit=to_commit,
        max_commits=max_commits,
    )

    if report.errors and not report.entries:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        content = render_drift_json(report)
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(content)
    elif not quiet:
        render_drift_table(report, console=console)


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--target",
    "target_python",
    default="3.12",
    help="Target Python version to check (default: 3.12).",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output compatibility report as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def compat(
    path: str,
    target_python: str,
    output_json: bool,
    quiet: bool,
) -> None:
    """Check Python version compatibility of dependencies.

    Analyzes your project's dependencies for compatibility with a
    target Python version using PyPI metadata (Requires-Python and
    classifiers). Identifies packages that will break on upgrade
    and computes an upgrade readiness score.

    PATH is the project directory (defaults to current directory).

    Examples:

    \b
    depcheck compat
    depcheck compat --target 3.13
    depcheck compat --target 3.11 --json
    depcheck compat /path/to/project
    """
    from depcheck.compat import (
        build_compat_report,
        render_compat_json,
        render_compat_table,
    )

    console = Console(quiet=quiet)

    report = build_compat_report(
        project_path=path,
        target_python=target_python,
    )

    if report.errors and not report.packages:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        content = render_compat_json(report)
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(content)
    elif not quiet:
        render_compat_table(report, console=console)

    # Exit with error if any packages are incompatible
    if report.incompatible_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
