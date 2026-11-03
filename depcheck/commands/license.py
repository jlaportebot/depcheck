"""Check dependency license compliance."""

from __future__ import annotations

import sys

import click
from rich.console import Console

from depcheck.commands import _common


@click.command(name="license")
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
def command(
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
    result = _common.scan_project(
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
