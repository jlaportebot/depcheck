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
            title="⚠️  Vulnerability Details",
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
        fail_on: The fail-on criteria ("vulnerable", "outdated", "unmaintained", "any", or None).

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
    elif fail_on in ("any", "all"):
        return 1 if result.has_issues() else 0
    else:
        return 0
