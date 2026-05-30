"""Command-line interface for depcheck."""

from __future__ import annotations

import sys
from pathlib import Path

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
    help="Output update plan as JSON.",
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
    output_json: bool,
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
            pkg.name for pkg in result.packages
            if pkg.installed_version and pkg.installed_version != "unknown"
        }

    plan = build_update_plan(result, pinned_packages=pinned_set)

    if output_json:
        content = render_update_plan_json(plan)
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
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
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
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
    help="Output size report as JSON.",
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
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
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
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
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
        clean_console = Console(
            quiet=False, force_terminal=False, no_color=True
        ) if quiet else Console(force_terminal=False, no_color=True)
        clean_console.print(content)
    elif not quiet:
        render_compat_table(report, console=console)

    # Exit with error if any packages are incompatible
    if report.incompatible_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
