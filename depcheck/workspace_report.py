"""Workspace report rendering for depcheck."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

if TYPE_CHECKING:
    from depcheck.workspace import WorkspaceScanResult
    from depcheck.workspace_analysis import WorkspaceAnalysis


@dataclass
class WorkspaceHealthGrade:
    """Health grade for a workspace."""

    grade: str
    score: float
    color: str


def calculate_workspace_grade(workspace_result: WorkspaceScanResult) -> WorkspaceHealthGrade:
    """Calculate overall workspace health grade.

    A: 0-10 risk score
    B: 11-30
    C: 31-50
    D: 51-70
    F: 71-100
    """
    total_packages = workspace_result.total_packages
    if total_packages == 0:
        return WorkspaceHealthGrade(grade="A", score=0.0, color="green")

    total_vulns = workspace_result.total_vulnerabilities
    # Simple risk score: 0-100 based on vulnerability ratio and count
    vuln_ratio = total_vulns / total_packages if total_packages > 0 else 0
    score = min(100, vuln_ratio * 100 + total_vulns * 5)

    if score <= 10:
        return WorkspaceHealthGrade(grade="A", score=score, color="green")
    elif score <= 30:
        return WorkspaceHealthGrade(grade="B", score=score, color="green")
    elif score <= 50:
        return WorkspaceHealthGrade(grade="C", score=score, color="yellow")
    elif score <= 70:
        return WorkspaceHealthGrade(grade="D", score=score, color="orange3")
    else:
        return WorkspaceHealthGrade(grade="F", score=score, color="red")


def render_workspace_table(
    workspace_result: WorkspaceScanResult,
    analysis: WorkspaceAnalysis | None = None,
    console: Console | None = None,
) -> None:
    """Render workspace scan results as a Rich table.

    Args:
        workspace_result: The workspace scan result to render.
        analysis: Optional cross-project analysis results.
        console: Rich console to render to.
    """
    if console is None:
        console = Console()

    # Grade panel
    grade = calculate_workspace_grade(workspace_result)
    grade_panel = Panel(
        f"[bold {grade.color}]{grade.grade}[/bold {grade.color}]",
        title=f"[bold]Workspace Health Grade[/bold] (Score: {grade.score:.1f}/100)",
        border_style=grade.color,
        padding=(1, 4),
    )
    console.print(grade_panel)
    console.print()

    # Summary table
    summary_table = Table(title="Workspace Summary", show_header=True, header_style="bold cyan")
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Value", justify="right")

    summary_table.add_row("Workspace Type", workspace_result.workspace_type.value.upper())
    summary_table.add_row("Root Path", str(workspace_result.root))
    summary_table.add_row("Member Projects", str(len(workspace_result.members)))
    summary_table.add_row("Total Packages", str(workspace_result.total_packages))
    summary_table.add_row("Total Vulnerabilities", str(workspace_result.total_vulnerabilities))

    if workspace_result.errors:
        summary_table.add_row("Errors", str(len(workspace_result.errors)))

    console.print(summary_table)
    console.print()

    # Member projects table
    if workspace_result.members:
        member_table = Table(title="Member Projects", show_header=True, header_style="bold cyan")
        member_table.add_column("Name", style="bold")
        member_table.add_column("Path")
        member_table.add_column("Packages", justify="right")
        member_table.add_column("Vulnerabilities", justify="right")
        member_table.add_column("Status")

        for member in workspace_result.members:
            pkg_count: int = 0
            vuln_count: int = 0
            status = "healthy"
            if member.scan_result and hasattr(member.scan_result, "packages"):
                pkg_count = len(member.scan_result.packages)
            if member.scan_result and hasattr(member.scan_result, "vulnerable_count"):
                vuln_count = int(member.scan_result.vulnerable_count)
            elif member.scan_result and hasattr(member.scan_result, "severity_breakdown"):
                sb = member.scan_result.severity_breakdown
                if hasattr(sb, "total"):
                    vuln_count = int(getattr(sb, "total", 0))

            if vuln_count > 0:
                status = "[red]vulnerable[/red]"
            elif pkg_count == 0:
                status = "[yellow]no deps[/yellow]"

            member_table.add_row(
                member.name,
                str(member.relative_path),
                str(pkg_count),
                str(vuln_count),
                status,
            )

        console.print(member_table)
        console.print()

    # Cross-project analysis
    if analysis:
        # Shared dependencies
        if analysis.shared_dependencies:
            shared_table = Table(
                title="Shared Dependencies", show_header=True, header_style="bold cyan"
            )
            shared_table.add_column("Package", style="bold")
            shared_table.add_column("Members", justify="right")
            shared_table.add_column("Versions")
            shared_table.add_column("Conflict")

            for name, shared in sorted(analysis.shared_dependencies.items()):
                versions_str = ", ".join(f"{m}: {v}" for m, v in sorted(shared.versions.items()))
                conflict_str = (
                    "[red]YES[/red]" if shared.has_version_conflict else "[green]NO[/green]"
                )
                shared_table.add_row(
                    name,
                    str(len(shared.members)),
                    versions_str,
                    conflict_str,
                )
            console.print(shared_table)
            console.print()

        # Version conflicts
        if analysis.version_conflicts:
            conflict_table = Table(
                title="Version Conflicts", show_header=True, header_style="bold red"
            )
            conflict_table.add_column("Package", style="bold")
            conflict_table.add_column("Versions")

            for conflict in analysis.version_conflicts:
                versions_str = ", ".join(f"{m}: {v}" for m, v in sorted(conflict.versions.items()))
                conflict_table.add_row(conflict.name, versions_str)

            console.print(conflict_table)
            console.print()

        # Consolidation opportunities
        if analysis.consolidation_opportunities:
            cons_table = Table(
                title="Consolidation Opportunities",
                show_header=True,
                header_style="bold green",
            )
            cons_table.add_column("Package", style="bold")
            cons_table.add_column("Members", justify="right")
            cons_table.add_column("Recommended Version")
            cons_table.add_column("Reason")

            for opp in analysis.consolidation_opportunities:
                cons_table.add_row(
                    opp.name,
                    str(opp.member_count),
                    opp.recommended_version or "N/A",
                    opp.reason,
                )
            console.print(cons_table)
            console.print()

    # Errors
    if workspace_result.errors:
        console.print("[bold red]Errors:[/bold red]")
        for error in workspace_result.errors:
            console.print(f"  [red]✗[/red] {error}")


def render_workspace_json(
    workspace_result: WorkspaceScanResult,
    analysis: WorkspaceAnalysis | None = None,
) -> str:
    """Render workspace scan results as JSON.

    Args:
        workspace_result: The workspace scan result to render.
        analysis: Optional cross-project analysis results.

    Returns:
        JSON string representation.
    """
    import json

    grade = calculate_workspace_grade(workspace_result)

    output = {
        "workspace": {
            "type": workspace_result.workspace_type.value,
            "root": str(workspace_result.root),
            "member_count": len(workspace_result.members),
            "total_packages": workspace_result.total_packages,
            "total_vulnerabilities": workspace_result.total_vulnerabilities,
            "grade": grade.grade,
            "score": round(grade.score, 1),
            "errors": workspace_result.errors,
        },
        "members": [],
    }

    for member in workspace_result.members:
        pkg_count: int = 0
        vuln_count: int = 0
        if member.scan_result and hasattr(member.scan_result, "packages"):
            pkg_count = len(member.scan_result.packages)
        if member.scan_result and hasattr(member.scan_result, "vulnerable_count"):
            vuln_count = int(member.scan_result.vulnerable_count)
        elif member.scan_result and hasattr(member.scan_result, "severity_breakdown"):
            sb = member.scan_result.severity_breakdown
            if hasattr(sb, "total"):
                vuln_count = int(getattr(sb, "total", 0))

        output["members"].append(
            {
                "name": member.name,
                "path": str(member.relative_path),
                "packages": pkg_count,
                "vulnerabilities": vuln_count,
            }
        )

    if analysis:
        output["analysis"] = {
            "shared_dependencies": {
                name: {
                    "members": shared.members,
                    "versions": shared.versions,
                    "has_version_conflict": shared.has_version_conflict,
                }
                for name, shared in analysis.shared_dependencies.items()
            },
            "version_conflicts": [
                {
                    "package": c.name,
                    "versions": c.versions,
                    "members": c.members,
                }
                for c in analysis.version_conflicts
            ],
            "consolidation_opportunities": [
                {
                    "package": o.name,
                    "member_count": o.member_count,
                    "recommended_version": o.recommended_version,
                    "reason": o.reason,
                }
                for o in analysis.consolidation_opportunities
            ],
            "total_unique_packages": analysis.total_unique_packages,
            "total_packages": analysis.total_packages,
        }

    return json.dumps(output, indent=2)
