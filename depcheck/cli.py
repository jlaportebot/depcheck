"""Command-line interface for depcheck."""

from __future__ import annotations

import json
import sys
from pathlib import Path

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
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster).",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Include license compliance info in annotations.",
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
    "--output",
    "output_file",
    type=click.Path(dir_okay=False, writable=True),
    default=None,
    help="Write annotations to file instead of stdout (useful for GitHub Actions).",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def annotations(
    path: str,
    no_vuln_check: bool,
    check_licenses: bool,
    fail_on: str | None,
    output_file: str | None,
    quiet: bool,
) -> None:
    """Generate GitHub Actions annotations for dependency issues.

    Outputs annotations in GitHub Actions format:
    ::error|warning|notice file=...,line=...::message

    This is useful for CI/CD pipelines to surface dependency issues
    directly in the GitHub Actions log and PR checks.

    PATH is the project directory to scan (defaults to current directory).

    Examples:

    \b
    depcheck annotations
    depcheck annotations --output annotations.txt
    depcheck annotations --fail-on vulnerable
    depcheck annotations /path/to/project
    """
    from depcheck.output import render_github_annotations
    from depcheck.scanner import scan_project

    console = Console(quiet=quiet)

    # Run the scan
    result = scan_project(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
        check_licenses=check_licenses,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Generate annotations
    annotations_list = render_github_annotations(result)

    # Output annotations
    if output_file:
        with open(output_file, "w") as f:
            for ann in annotations_list:
                f.write(
                    f"::{ann['type']} file={ann['file']},line={ann['line']}::{ann['message']}\n"
                )
        if not quiet:
            console.print(f"[green]Annotations written to {output_file}[/green]")
            console.print(f"[dim]{len(annotations_list)} annotations generated[/dim]")
    else:
        for ann in annotations_list:
            print(f"::{ann['type']} file={ann['file']},line={ann['line']}::{ann['message']}")

    # Determine exit code based on fail-on criteria
    exit_code = determine_exit_code(result, fail_on)
    if exit_code != 0 and not quiet:
        if fail_on:
            console.print(
                f"[red]✗ Annotations check failed: --fail-on {fail_on} condition met[/red]"
            )

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
            category_map[cat.lower()] for cat in allowed_licenses if cat.lower() in category_map
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
    "--strategy",
    type=click.Choice(["newest", "oldest", "minimum_compatible"], case_sensitive=False),
    default="newest",
    help="Resolution strategy for picking versions (default: newest).",
)
@click.option(
    "--format",
    "lockfile_format",
    type=click.Choice(["depcheck", "pip", "pipenv", "poetry"], case_sensitive=False),
    default="depcheck",
    help="Lockfile output format (default: depcheck).",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    default=None,
    type=click.Path(),
    help="Write lockfile to file instead of stdout.",
)
@click.option(
    "--python-version",
    default="3.12",
    help="Python version for compatibility filtering (default: 3.12).",
)
@click.option(
    "--allow-prerelease",
    is_flag=True,
    default=False,
    help="Include pre-release versions in resolution.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output resolution results as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def resolve(
    path: str,
    strategy: str,
    lockfile_format: str,
    output_path: str | None,
    python_version: str,
    allow_prerelease: bool,
    output_json: bool,
    quiet: bool,
) -> None:
    """Resolve all dependencies into a compatible version set.

    Performs constraint solving across the full dependency graph to find
    a set of package versions that satisfies all requirements. Generates
    a lockfile in your preferred format.

    PATH is the project directory to resolve (defaults to current directory).

    Examples:

    \\b
    depcheck resolve
    depcheck resolve --strategy oldest
    depcheck resolve --format pip --output requirements.lock
    depcheck resolve --format poetry --output poetry.lock
    depcheck resolve --json
    depcheck resolve --allow-prerelease
    """
    from depcheck.resolve import (
        LockfileFormat,
        ResolutionStrategy,
        generate_lockfile,
        render_resolve_json,
        render_resolve_table,
        resolve_project,
    )

    console = Console(quiet=quiet)

    strategy_map = {
        "newest": ResolutionStrategy.NEWEST,
        "oldest": ResolutionStrategy.OLDEST,
        "minimum_compatible": ResolutionStrategy.MINIMUM_COMPATIBLE,
    }
    format_map = {
        "depcheck": LockfileFormat.DEPCHECK,
        "pip": LockfileFormat.PIP,
        "pipenv": LockfileFormat.PIPENV,
        "poetry": LockfileFormat.POETRY,
    }

    if not quiet:
        console.print("[bold]Resolving dependencies...[/bold]")

    result = resolve_project(
        project_path=path,
        strategy=strategy_map[strategy.lower()],
        python_version=python_version,
        allow_prerelease=allow_prerelease,
    )

    if result.errors and not result.resolved:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    # Output lockfile
    lockfile_content = generate_lockfile(
        result,
        format=format_map[lockfile_format.lower()],
        project_name=Path(path).resolve().name,
    )

    if output_path:
        Path(output_path).write_text(lockfile_content, encoding="utf-8")
        if not quiet:
            console.print(f"[green]✓ Lockfile written to {output_path}[/green]")
            console.print(
                f"  Resolved {len(result.resolved)} packages, "
                f"{result.conflict_count} conflicts in "
                f"{result.resolution_time_ms:.1f}ms"
            )
    elif output_json:
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(render_resolve_json(result))
    else:
        if not quiet:
            render_resolve_table(result, console=console)

    # Exit code
    if result.has_conflicts:
        sys.exit(1)


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--policy",
    type=click.Choice(["exact", "compatible", "minimum"], case_sensitive=False),
    default="exact",
    help="Pin policy: exact (==), compatible (~=), or minimum (>=).",
)
@click.option(
    "--no-hashes",
    is_flag=True,
    default=False,
    help="Skip hash verification data in the pinfile.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output pin results as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def pin(
    path: str,
    policy: str,
    no_hashes: bool,
    output_json: bool,
    quiet: bool,
) -> None:
    """Pin all dependencies to their current versions with integrity metadata.

    Creates a depcheck.pin.json file that records exact versions and
    optional SHA-256 hashes for every dependency. Use 'depcheck verify'
    to check integrity against the pinfile later.

    PATH is the project directory to pin (defaults to current directory).

    Examples:

    \\b
    depcheck pin
    depcheck pin --policy compatible
    depcheck pin --no-hashes
    depcheck pin --json
    """
    from depcheck.pin import PinPolicy, pin_packages, render_pin_json, render_pin_table

    console = Console(quiet=quiet)

    policy_map = {
        "exact": PinPolicy.EXACT,
        "compatible": PinPolicy.COMPATIBLE,
        "minimum": PinPolicy.MINIMUM,
    }

    result = pin_packages(
        project_path=path,
        policy=policy_map[policy.lower()],
        include_hashes=not no_hashes,
    )

    if output_json:
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(render_pin_json(result))
    elif not quiet:
        render_pin_table(result, console=console)

    if result.errors:
        sys.exit(2)


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
)
@click.option(
    "--no-hash-check",
    is_flag=True,
    default=False,
    help="Skip hash integrity checking.",
)
@click.option(
    "--no-version-check",
    is_flag=True,
    default=False,
    help="Skip version consistency checking.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output integrity report as JSON.",
)
@click.option(
    "--fail-on",
    type=click.Choice(["warning", "critical", "any"], case_sensitive=False),
    default=None,
    help="Exit with code 1 if issues at the specified severity are found.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def verify(
    path: str,
    no_hash_check: bool,
    no_version_check: bool,
    output_json: bool,
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Verify pinned dependency integrity against installed versions.

    Checks that installed packages match their pinned versions, verifies
    hash integrity, and flags yanked or deprecated packages.

    PATH is the project directory to verify (defaults to current directory).

    Examples:

    \\b
    depcheck verify
    depcheck verify --json
    depcheck verify --fail-on critical
    depcheck verify --no-hash-check
    """
    from depcheck.pin import (
        Severity,
        render_integrity_json,
        render_integrity_table,
        verify_integrity,
    )

    console = Console(quiet=quiet)

    report = verify_integrity(
        project_path=path,
        check_hashes=not no_hash_check,
        check_versions=not no_version_check,
    )

    if report.errors and not report.checks:
        for error in report.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(render_integrity_json(report))
    elif not quiet:
        render_integrity_table(report, console=console)

    # Exit code
    if fail_on:
        severity_map = {
            "any": Severity.OK,
            "warning": Severity.WARNING,
            "critical": Severity.CRITICAL,
        }
        threshold = severity_map.get(fail_on.lower(), Severity.CRITICAL)
        level_order = {Severity.OK: 0, Severity.WARNING: 1, Severity.CRITICAL: 2}
        if level_order.get(report.overall_severity, 0) >= level_order.get(threshold, 2):
            if not quiet:
                console.print(
                    f"[red]✗ Integrity check failed: {report.overall_severity.value} "
                    f"issues meet or exceed --fail-on {fail_on} threshold[/red]"
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
    help="Output drift report as JSON.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def drift(
    path: str,
    output_json: bool,
    quiet: bool,
) -> None:
    """Detect drift between pinned versions and latest available versions.

    Compares your pinfile against the latest versions available on PyPI
    and reports which packages have drifted, classified by severity
    (major/minor/patch) and whether they include security updates.

    PATH is the project directory to check for drift (defaults to current directory).

    Examples:

    \\b
    depcheck drift
    depcheck drift --json
    """
    from depcheck.pin import (
        detect_pin_drift,
        render_drift_json,
        render_drift_table,
    )

    console = Console(quiet=quiet)

    report = detect_pin_drift(project_path=path)

    if output_json:
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(render_drift_json(report))
    elif not quiet:
        render_drift_table(report, console=console)

    # Exit with code 1 if there are significant drifts
    if report.significant_drifts:
        sys.exit(1)


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output as JSON.",
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
    help="Suppress non-essential output.",
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

    \b
    Examples:
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
        print(render_suggest_json(result))
    else:
        render_suggest_table(result, console=console)

    if result.errors:
        sys.exit(2)


@main.command()
@click.argument(
    "path",
    default=".",
    type=click.Path(exists=False, file_okay=False, dir_okay=True),
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output as JSON.",
)
@click.option(
    "--package",
    "packages",
    multiple=True,
    help="Specific packages to analyze (can be repeated).",
)
@click.option(
    "--risk-threshold",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default=None,
    help="Only show packages at or above this risk level.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress non-essential output.",
)
def history(
    path: str,
    output_json: bool,
    packages: tuple[str, ...],
    risk_threshold: str | None,
    quiet: bool,
) -> None:
    """Analyze release timeline and maintenance patterns.

    Shows release cadence, version gaps, lifecycle stage, and risk
    assessment for each dependency.

    \b
    Examples:
        depcheck history
        depcheck history /path/to/project --json
        depcheck history . --package requests --package flask
        depcheck history . --risk-threshold high
    """
    from depcheck.history import build_history_report, render_history_json, render_history_table

    console = Console(quiet=quiet)
    result = build_history_report(
        project_path=path,
        packages=list(packages) if packages else None,
        risk_threshold=risk_threshold,
    )

    if output_json:
        clean_console = (
            Console(quiet=False, force_terminal=False, no_color=True)
            if quiet
            else Console(force_terminal=False, no_color=True)
        )
        clean_console.print(render_history_json(result))
    else:
        render_history_table(result, console=console)

    if result.errors:
        sys.exit(2)


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
    has_cli_overrides = any(
        [
            max_packages is not None,
            max_download_kb is not None,
            max_install_kb is not None,
            max_single_package_kb is not None,
            allowed_licenses,
            denied_packages,
            required_packages,
        ]
    )

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
            config.denied_packages = {normalize_package_name(p) for p in denied_packages}
        if required_packages:
            config.required_packages = {normalize_package_name(p) for p in required_packages}

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


# ── New commands: risks, advisories, policy ────────────────────────────


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
    help="Minimum severity to report.",
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


# ── New commands: update, isolate, sizescore, depdrift, compat ─────────


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
            pkg.name
            for pkg in result.packages
            if pkg.installed_version and pkg.installed_version != "unknown"
        }

    plan = build_update_plan(result, pinned_packages=pinned_set)

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
    default=None,
    help="Starting git commit for drift comparison.",
)
@click.option(
    "--to-commit",
    default=None,
    help="Ending git commit for drift comparison.",
)
@click.option(
    "--max-commits",
    type=int,
    default=100,
    help="Maximum number of commits to traverse.",
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
    default="3.13",
    help="Target Python version for compatibility check.",
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


# ── New commands: predict, stack ───────────────────────────────────────


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
    help="Output predictions as JSON.",
)
@click.option(
    "--no-vuln-check",
    is_flag=True,
    default=False,
    help="Skip vulnerability checking (faster).",
)
@click.option(
    "--fail-on",
    type=click.Choice(["moderate", "high", "critical"]),
    default=None,
    help="Exit with code 1 if deprecation risk meets threshold.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def predict(
    path: str,
    output_json: bool,
    no_vuln_check: bool,
    fail_on: str | None,
    quiet: bool,
) -> None:
    """Predict version releases and detect deprecation risk for dependencies.

    Analyzes package release history to predict next version numbers,
    estimate release cadence, detect deprecation signals, and calculate
    a comprehensive deprecation risk score for each dependency.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck predict
    depcheck predict --json
    depcheck predict --fail-on high
    depcheck predict /path/to/project
    """
    from depcheck.predict import (
        DeprecationRiskLevel,
        render_predict_json,
        render_predict_table,
        run_predict,
    )

    console = Console(quiet=quiet)

    result = run_predict(
        project_path=path,
        check_vulnerabilities=not no_vuln_check,
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_predict_json(result)
    elif not quiet:
        render_predict_table(result, console=console)

    if fail_on:
        threshold_map = {
            "moderate": DeprecationRiskLevel.MODERATE,
            "high": DeprecationRiskLevel.HIGH,
            "critical": DeprecationRiskLevel.CRITICAL,
        }
        threshold = threshold_map.get(fail_on.lower(), DeprecationRiskLevel.CRITICAL)
        level_order = {
            DeprecationRiskLevel.LOW: 0,
            DeprecationRiskLevel.MODERATE: 1,
            DeprecationRiskLevel.HIGH: 2,
            DeprecationRiskLevel.CRITICAL: 3,
        }
        if level_order.get(result.overall_deprecation_risk, 0) >= level_order.get(threshold, 3):
            if not quiet:
                console.print(
                    f"[red]✗ Predict failed: deprecation risk "
                    f"{result.overall_deprecation_risk.value} "
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
    help="Output stack analysis as JSON.",
)
@click.option(
    "--check-licenses",
    is_flag=True,
    default=False,
    help="Also check license chain compliance.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress all output except errors and exit code.",
)
def stack(
    path: str,
    output_json: bool,
    check_licenses: bool,
    quiet: bool,
) -> None:
    """Analyze your project's tech stack and detect conflicts.

    Automatically detects the technology stack by analyzing dependencies
    and configuration files. Checks for version conflicts, known
    incompatibilities between packages, and optionally checks license
    chain compliance across your dependency tree.

    PATH is the project directory to analyze (defaults to current directory).

    Examples:

    \b
    depcheck stack
    depcheck stack --json
    depcheck stack --check-licenses
    depcheck stack /path/to/project
    """
    from depcheck.stack import render_stack_json, render_stack_table, run_stack

    console = Console(quiet=quiet)

    result = run_stack(
        project_path=path,
        check_licenses=check_licenses,
    )

    if result.errors and not result.components:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        sys.exit(2)

    if output_json:
        render_stack_json(result)
    elif not quiet:
        render_stack_table(result, console=console)

    # Exit with error if there are critical conflicts
    has_critical = any(c.severity.value == "critical" for c in result.conflicts)
    if has_critical:
        sys.exit(1)


if __name__ == "__main__":
    main()
