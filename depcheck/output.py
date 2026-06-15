"""Rich-formatted output for depcheck scan results."""

from __future__ import annotations

import json

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import HealthStatus, ScanResult

# Status icons and colors
STATUS_STYLES: dict[HealthStatus, tuple[str, str]] = {
    HealthStatus.HEALTHY: ("🟢", "green"),
    HealthStatus.OUTDATED: ("🟡", "yellow"),
    HealthStatus.VULNERABLE: ("🔴", "red"),
    HealthStatus.UNMAINTAINED: ("🟡", "yellow"),
    HealthStatus.YANKED: ("🔴", "red"),
    HealthStatus.REMOVED: ("🔴", "red"),
    HealthStatus.UNKNOWN: ("⚪", "white"),
}


def _status_icon(status: HealthStatus) -> str:
    """Get the icon for a health status."""
    return STATUS_STYLES.get(status, ("⚪", "white"))[0]


def _status_color(status: HealthStatus) -> str:
    """Get the color for a health status."""
    return STATUS_STYLES.get(status, ("⚪", "white"))[1]


def _license_category_style(category: str) -> tuple[str, str]:
    """Get icon and color for a license category."""
    styles = {
        "permissive": ("✅", "green"),
        "copyleft": ("⚠️", "yellow"),
        "public_domain": ("✅", "green"),
        "restricted": ("🚫", "red"),
        "proprietary": ("🚫", "red"),
        "unknown": ("❓", "white"),
    }
    return styles.get(category, ("❓", "white"))


def render_table(result: ScanResult, console: Console | None = None) -> None:
    """Render a Rich table showing the scan results.

    Args:
        result: The scan result to render.
        console: Optional Rich console to use (creates one if not provided).
    """
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]depcheck[/bold] — Dependency Health Report\n"
            f"[dim]Project: {result.project_path}[/dim]",
            border_style="blue",
        )
    )

    if result.errors and not result.packages:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        return

    # Main table
    table = Table(
        title="Package Health Status",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        pad_edge=False,
        expand=True,
    )

    table.add_column("Status", width=4, justify="center")
    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Installed", min_width=12)
    table.add_column("Latest", min_width=12)
    table.add_column("Last Release", min_width=12)
    table.add_column("Issues", min_width=30)

    for pkg in result.packages:
        icon = _status_icon(pkg.status)
        color = _status_color(pkg.status)

        # Build issues string
        issues: list[str] = []
        if pkg.status == HealthStatus.VULNERABLE:
            vuln_count = len(pkg.vulnerabilities)
            vuln_label = "vulnerability" if vuln_count == 1 else "vulnerabilities"
            issues.append(f"[red]{vuln_count} {vuln_label}[/red]")
            # Show first vulnerability summary
            if pkg.vulnerabilities:
                worst = max(
                    pkg.vulnerabilities,
                    key=lambda v: {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(v.severity, 0),
                )
                issues.append(f"[dim red]{worst.vuln_id}: {worst.summary[:50]}[/dim red]")
        elif pkg.status == HealthStatus.OUTDATED:
            issues.append("[yellow]Newer version available[/yellow]")
        elif pkg.status == HealthStatus.UNMAINTAINED:
            issues.append("[yellow]No updates in 1+ year[/yellow]")
        elif pkg.status == HealthStatus.YANKED:
            issues.append("[red]Version yanked from PyPI[/red]")
        elif pkg.status == HealthStatus.REMOVED:
            issues.append("[red]Package removed from PyPI[/red]")
        elif pkg.status == HealthStatus.UNKNOWN:
            if pkg.error:
                issues.append(f"[white]{pkg.error[:50]}[/white]")

        # License issues
        if pkg.license_info and not pkg.license_info.is_compliant:
            is_restricted = pkg.license_info.category in ("restricted", "copyleft")
            lic_color = "red" if is_restricted else "yellow"
            lic_text = pkg.license_info.spdx_id or "Unknown"
            issues.append(f"[{lic_color}]⚖ License: {lic_text}[/{lic_color}]")
            if pkg.license_info.compliance_note:
                note = pkg.license_info.compliance_note[:60]
                issues.append(f"[dim {lic_color}]{note}[/dim {lic_color}]")

        issues_str = "\n".join(issues) if issues else "[green]OK[/green]"

        table.add_row(
            icon,
            f"[{color}]{pkg.name}[/{color}]",
            pkg.installed_version or "—",
            pkg.latest_version or "—",
            pkg.last_release_date or "—",
            issues_str,
        )

    console.print(table)

    # Vulnerability details
    vuln_packages = [p for p in result.packages if p.vulnerabilities]
    if vuln_packages:
        console.print()
        vuln_table = Table(
            title="⚠️ Vulnerability Details",
            show_header=True,
            header_style="bold red",
            show_lines=False,
            expand=True,
        )
        vuln_table.add_column("Package", style="bold", min_width=20)
        vuln_table.add_column("ID", min_width=15)
        vuln_table.add_column("Severity", min_width=10)
        vuln_table.add_column("Summary", min_width=40)
        vuln_table.add_column("URL", min_width=30, no_wrap=True)

        for pkg in vuln_packages:
            for vuln in pkg.vulnerabilities:
                severity_color = {
                    "HIGH": "red",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                }.get(vuln.severity, "white")

                vuln_table.add_row(
                    pkg.name,
                    vuln.vuln_id,
                    f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                    vuln.summary[:60] + ("..." if len(vuln.summary) > 60 else ""),
                    f"[link={vuln.url}]{vuln.url}[/link]",
                )

        console.print(vuln_table)

    # License details
    license_packages = [p for p in result.packages if p.license_info is not None]
    if license_packages:
        console.print()
        lic_table = Table(
            title="⚖️ License Summary",
            show_header=True,
            header_style="bold magenta",
            show_lines=False,
            expand=True,
        )
        lic_table.add_column("Package", style="bold", min_width=20)
        lic_table.add_column("License", min_width=15)
        lic_table.add_column("Category", min_width=12)
        lic_table.add_column("Status", min_width=10)

        for pkg in license_packages:
            lic = pkg.license_info
            assert lic is not None  # Guaranteed by filter above
            lic_icon, lic_color = _license_category_style(lic.category)
            status_text = "✅ Compliant" if lic.is_compliant else "❌ Non-compliant"
            status_color = "green" if lic.is_compliant else "red"

            lic_table.add_row(
                pkg.name,
                lic.spdx_id or lic.raw_license or "Unknown",
                f"[{lic_color}]{lic_icon} {lic.category}[/{lic_color}]",
                f"[{status_color}]{status_text}[/{status_color}]",
            )

        console.print(lic_table)

    # Summary panel
    console.print()
    summary_parts: list[str] = []
    summary_parts.append(f"[bold]Total:[/bold] {result.total} packages")

    if result.healthy_count:
        summary_parts.append(f"[green]🟢 Healthy: {result.healthy_count}[/green]")
    if result.outdated_count:
        summary_parts.append(f"[yellow]🟡 Outdated: {result.outdated_count}[/yellow]")
    if result.vulnerable_count:
        summary_parts.append(f"[red]🔴 Vulnerable: {result.vulnerable_count}[/red]")
    if result.unmaintained_count:
        summary_parts.append(f"[yellow]🟡 Unmaintained: {result.unmaintained_count}[/yellow]")
    if result.yanked_count:
        summary_parts.append(f"[red]🔴 Yanked: {result.yanked_count}[/red]")
    if result.removed_count:
        summary_parts.append(f"[red]🔴 Removed: {result.removed_count}[/red]")
    if result.license_issues_count:
        summary_parts.append(f"[red]⚖ License issues: {result.license_issues_count}[/red]")

    if result.files_scanned:
        summary_parts.append(f"\n[dim]Scanned: {', '.join(result.files_scanned)}[/dim]")

    console.print(Panel("\n".join(summary_parts), title="Summary", border_style="blue"))
    console.print()


def render_json(result: ScanResult, console: Console | None = None) -> None:
    """Render scan results as JSON output.

    Args:
        result: The scan result to render.
        console: Optional Rich console to use.
    """
    if console is None:
        console = Console()

    data = result.to_dict()
    console.print_json(json.dumps(data, indent=2))


def determine_exit_code(result: ScanResult, fail_on: str | None = None) -> int:
    """Determine the exit code based on scan results and fail-on criteria.

    Args:
        result: The scan result.
        fail_on: The fail-on criteria ("vulnerable", "outdated", "unmaintained",
            "license", "any", or None).

    Returns:
        Exit code: 0 if passing, 1 if failing, 2 if errors occurred.
    """
    if result.errors and not result.packages:
        return 2

    if fail_on is None:
        return 0

    fail_on = fail_on.lower().strip()

    if fail_on == "vulnerable":
        return 1 if result.has_vulnerabilities() else 0
    elif fail_on == "outdated":
        return 1 if result.outdated_count > 0 else 0
    elif fail_on == "unmaintained":
        return 1 if result.unmaintained_count > 0 else 0
    elif fail_on == "license":
        return 1 if result.license_issues_count > 0 else 0
    elif fail_on in ("any", "all"):
        has_any = result.has_issues() or result.license_issues_count > 0
        return 1 if has_any else 0
    else:
        return 0


def render_github_annotations(result: ScanResult) -> list[dict]:
    """Render scan results as GitHub Actions annotations.

    Args:
        result: The scan result to render.

    Returns:
        List of annotation dictionaries compatible with GitHub Actions
        `::notice|warning|error file=...,line=...::message` format.
        Each dict has keys: type (error|warning|notice), file, line, message.
    """
    annotations: list[dict] = []

    for pkg in result.packages:
        # Vulnerabilities -> error annotations (one per vulnerability)
        if pkg.vulnerabilities:
            for vuln in pkg.vulnerabilities:
                severity_label = vuln.severity.capitalize() if vuln.severity else "Unknown"
                msg = (
                    f"{pkg.name} {pkg.installed_version}: "
                    f"{vuln.vuln_id} ({severity_label}) - {vuln.summary}"
                )
                annotations.append(
                    {
                        "type": "error",
                        "file": "pyproject.toml",  # Generic file since we don't track exact location
                        "line": 1,
                        "message": msg,
                    }
                )

        # Yanked/Removed -> error annotations
        if pkg.status == HealthStatus.YANKED:
            annotations.append(
                {
                    "type": "error",
                    "file": "pyproject.toml",
                    "line": 1,
                    "message": f"{pkg.name} {pkg.installed_version}: Version yanked from PyPI",
                }
            )
        elif pkg.status == HealthStatus.REMOVED:
            annotations.append(
                {
                    "type": "error",
                    "file": "pyproject.toml",
                    "line": 1,
                    "message": f"{pkg.name} {pkg.installed_version}: Package removed from PyPI",
                }
            )

        # Outdated -> warning annotations
        if pkg.status == HealthStatus.OUTDATED:
            annotations.append(
                {
                    "type": "warning",
                    "file": "pyproject.toml",
                    "line": 1,
                    "message": (
                        f"{pkg.name}: installed {pkg.installed_version}, "
                        f"latest {pkg.latest_version} available"
                    ),
                }
            )

        # Unmaintained -> warning annotations
        if pkg.status == HealthStatus.UNMAINTAINED:
            annotations.append(
                {
                    "type": "warning",
                    "file": "pyproject.toml",
                    "line": 1,
                    "message": (
                        f"{pkg.name} {pkg.installed_version}: No updates in 1+ year (unmaintained)"
                    ),
                }
            )

        # License issues -> warning annotations
        if pkg.license_info and not pkg.license_info.is_compliant:
            lic = pkg.license_info
            msg = (
                f"{pkg.name}: License compliance issue - "
                f"{lic.spdx_id or 'Unknown'} ({lic.category})"
            )
            if lic.compliance_note:
                msg += f" - {lic.compliance_note}"
            annotations.append(
                {
                    "type": "warning",
                    "file": "pyproject.toml",
                    "line": 1,
                    "message": msg,
                }
            )

    return annotations
