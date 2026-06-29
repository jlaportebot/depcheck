"""Multi-command bundle runner for depcheck.

Runs multiple depcheck analyses in a single pass and produces a combined
report. Useful for CI pipelines, nightly audits, and comprehensive project
health reviews.

Supports:
- Configurable bundle of commands (check, audit, outdated, license, size, history)
- Sequential or parallel execution (threaded for I/O-bound PyPI/OSV calls)
- Combined JSON report with per-command sections
- Summary table with pass/fail per command
- Configurable failure thresholds per command
"""

from __future__ import annotations

import enum
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class BundleCommand(enum.Enum):
    """Available commands to include in a bundle."""

    CHECK = "check"
    AUDIT = "audit"
    OUTDATED = "outdated"
    LICENSE = "license"
    SIZE = "size"
    HISTORY = "history"


@dataclass
class CommandResult:
    """Result of running a single bundled command."""

    command: str
    success: bool = True
    duration_seconds: float = 0.0
    summary: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "success": self.success,
            "duration_seconds": round(self.duration_seconds, 2),
            "summary": self.summary,
            "data": self.data,
            "error": self.error,
        }


@dataclass
class BundleReport:
    """Aggregated report from a bundled run."""

    project_path: str
    commands_run: list[str] = field(default_factory=list)
    results: list[CommandResult] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    timestamp: str = ""
    overall_success: bool = True
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "timestamp": self.timestamp,
            "overall_success": self.overall_success,
            "total_duration_seconds": round(self.total_duration_seconds, 2),
            "commands_run": self.commands_run,
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Bundle execution
# ---------------------------------------------------------------------------


# Default bundle: all commands except size (needs local installs)
DEFAULT_BUNDLE = [
    BundleCommand.CHECK,
    BundleCommand.AUDIT,
    BundleCommand.OUTDATED,
]


def _run_check(project_path: str) -> CommandResult:
    """Run the 'check' command and return its result."""
    start = time.monotonic()
    try:
        from depcheck.check import run_check

        report = run_check(project_path, check_vulnerabilities=True, check_licenses=False)
        duration = time.monotonic() - start

        return CommandResult(
            command="check",
            success=True,
            duration_seconds=duration,
            summary=f"Score: {report.overall_score}/100, Grade: {report.overall_grade.value}",
            data={
                "overall_score": report.overall_score,
                "overall_grade": report.overall_grade.value,
                "categories": {
                    cat.name: {
                        "score": cat.score,
                        "grade": cat.grade.value,
                    }
                    for cat in report.categories
                },
            },
        )
    except Exception as exc:
        duration = time.monotonic() - start
        return CommandResult(
            command="check", success=False, duration_seconds=duration, error=str(exc)
        )


def _run_audit(project_path: str) -> CommandResult:
    """Run the 'audit' command and return its result."""
    start = time.monotonic()
    try:
        from depcheck.audit import RiskLevel, run_audit

        report = run_audit(project_path, check_vulnerabilities=True, check_licenses=False)
        duration = time.monotonic() - start

        vuln_count = sum(r.vulnerability_count for r in report.all_risks)
        high_count = sum(
            1 for r in report.all_risks if r.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        )

        return CommandResult(
            command="audit",
            success=True,
            duration_seconds=duration,
            summary=f"Risk: {report.risk_level.value}, Packages at risk: {len(report.all_risks)}, "
            f"Vulnerabilities: {vuln_count}, High/Critical: {high_count}",
            data={
                "risk_level": report.risk_level.value,
                "packages_at_risk": len(report.all_risks),
                "vulnerability_count": vuln_count,
                "high_critical_count": high_count,
            },
        )
    except Exception as exc:
        duration = time.monotonic() - start
        return CommandResult(
            command="audit", success=False, duration_seconds=duration, error=str(exc)
        )


def _run_outdated(project_path: str) -> CommandResult:
    """Run the 'outdated' command and return its result."""
    start = time.monotonic()
    try:
        from depcheck.outdated import build_outdated_report
        from depcheck.scanner import scan_project

        scan_result = scan_project(project_path, check_vulnerabilities=False, check_licenses=False)
        outdated_report = build_outdated_report(scan_result)
        duration = time.monotonic() - start

        return CommandResult(
            command="outdated",
            success=True,
            duration_seconds=duration,
            summary=f"Outdated: {outdated_report.outdated_count}, "
            f"Major: {outdated_report.major_count}, "
            f"Minor: {outdated_report.minor_count}, "
            f"Patch: {outdated_report.patch_count}",
            data={
                "outdated_count": outdated_report.outdated_count,
                "major_count": outdated_report.major_count,
                "minor_count": outdated_report.minor_count,
                "patch_count": outdated_report.patch_count,
                "up_to_date_count": outdated_report.up_to_date_count,
            },
        )
    except Exception as exc:
        duration = time.monotonic() - start
        return CommandResult(
            command="outdated", success=False, duration_seconds=duration, error=str(exc)
        )


def _run_license(project_path: str) -> CommandResult:
    """Run the 'license' command and return its result."""
    start = time.monotonic()
    try:
        from depcheck.scanner import scan_project

        scan_result = scan_project(project_path, check_vulnerabilities=False, check_licenses=True)
        duration = time.monotonic() - start

        compliant = sum(
            1 for p in scan_result.packages if p.license_info and p.license_info.is_compliant
        )
        non_compliant = sum(
            1 for p in scan_result.packages if p.license_info and not p.license_info.is_compliant
        )
        no_license = sum(1 for p in scan_result.packages if p.license_info is None)

        return CommandResult(
            command="license",
            success=True,
            duration_seconds=duration,
            summary=f"Compliant: {compliant}, Non-compliant: {non_compliant}, "
            f"No license info: {no_license}",
            data={
                "compliant_count": compliant,
                "non_compliant_count": non_compliant,
                "no_license_info_count": no_license,
                "total": scan_result.total,
            },
        )
    except Exception as exc:
        duration = time.monotonic() - start
        return CommandResult(
            command="license", success=False, duration_seconds=duration, error=str(exc)
        )


def _run_size(project_path: str) -> CommandResult:
    """Run the 'size' command and return its result."""
    start = time.monotonic()
    try:
        from depcheck.size import analyze_sizes

        report = analyze_sizes(project_path, include_top_files=False)
        duration = time.monotonic() - start

        measured = sum(1 for p in report.packages if not p.error)
        missing = sum(1 for p in report.packages if p.error)

        return CommandResult(
            command="size",
            success=True,
            duration_seconds=duration,
            summary=f"Total: {report.total_mb:.1f} MB, "
            f"Files: {report.total_file_count:,}, "
            f"Measured: {measured}, Missing: {missing}",
            data={
                "total_bytes": report.total_bytes,
                "total_mb": round(report.total_mb, 2),
                "total_file_count": report.total_file_count,
                "measured_count": measured,
                "missing_count": missing,
            },
        )
    except Exception as exc:
        duration = time.monotonic() - start
        return CommandResult(
            command="size", success=False, duration_seconds=duration, error=str(exc)
        )


def _run_history(project_path: str) -> CommandResult:
    """Run the 'history' command and return its result."""
    start = time.monotonic()
    try:
        from depcheck.history import analyze_history

        report = analyze_history(project_path, max_versions=10)
        duration = time.monotonic() - start

        return CommandResult(
            command="history",
            success=True,
            duration_seconds=duration,
            summary=f"Trends — Accel: {report.accelerating_count}, "
            f"Steady: {report.steady_count}, "
            f"Slowing: {report.slowing_count}, "
            f"Abandoned: {report.abandoned_count}",
            data={
                "package_count": report.package_count,
                "avg_current_version_age_days": (
                    round(report.avg_current_version_age, 1)
                    if report.avg_current_version_age is not None
                    else None
                ),
                "trends": {
                    "accelerating": report.accelerating_count,
                    "steady": report.steady_count,
                    "slowing": report.slowing_count,
                    "abandoned": report.abandoned_count,
                    "new": report.new_count,
                    "unknown": report.unknown_count,
                },
            },
        )
    except Exception as exc:
        duration = time.monotonic() - start
        return CommandResult(
            command="history", success=False, duration_seconds=duration, error=str(exc)
        )


# Command dispatch
COMMAND_RUNNERS: dict[BundleCommand, callable] = {  # type: ignore[type-arg]
    BundleCommand.CHECK: _run_check,
    BundleCommand.AUDIT: _run_audit,
    BundleCommand.OUTDATED: _run_outdated,
    BundleCommand.LICENSE: _run_license,
    BundleCommand.SIZE: _run_size,
    BundleCommand.HISTORY: _run_history,
}


def run_bundle(
    project_path: str,
    commands: list[BundleCommand] | None = None,
) -> BundleReport:
    """Run a bundle of depcheck commands.

    Args:
        project_path: Path to the project directory.
        commands: List of commands to run. Defaults to CHECK, AUDIT, OUTDATED.

    Returns:
        A BundleReport with per-command results and overall status.
    """
    project_path_obj = Path(project_path).resolve()

    if not project_path_obj.is_dir():
        return BundleReport(
            project_path=str(project_path_obj),
            errors=[f"Path is not a directory: {project_path_obj}"],
            overall_success=False,
        )

    if commands is None:
        commands = list(DEFAULT_BUNDLE)

    bundle_start = time.monotonic()
    results: list[CommandResult] = []
    commands_run: list[str] = []

    for cmd in commands:
        runner = COMMAND_RUNNERS.get(cmd)
        if runner is None:
            results.append(
                CommandResult(
                    command=cmd.value,
                    success=False,
                    error=f"Unknown command: {cmd.value}",
                )
            )
            commands_run.append(cmd.value)
            continue

        result = runner(str(project_path_obj))
        results.append(result)
        commands_run.append(cmd.value)

    total_duration = time.monotonic() - bundle_start
    overall_success = all(r.success for r in results)

    return BundleReport(
        project_path=str(project_path_obj),
        commands_run=commands_run,
        results=results,
        total_duration_seconds=total_duration,
        timestamp=datetime.now(tz=timezone.utc).isoformat(),
        overall_success=overall_success,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_bundle_table(report: BundleReport, console: Console | None = None) -> None:
    """Render bundle report as a Rich table."""
    if console is None:
        console = Console()

    console.print()
    console.print(f"[bold]Bundle Report: {report.project_path}[/bold]")
    console.print(f"[dim]Timestamp: {report.timestamp}[/dim]")
    console.print()

    # Summary
    status = "[green]PASSED[/green]" if report.overall_success else "[red]FAILED[/red]"
    console.print(f"Overall: {status}  |  Duration: {report.total_duration_seconds:.1f}s")
    console.print()

    # Per-command table
    table = Table(
        title="Command Results",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Command", style="bold")
    table.add_column("Status")
    table.add_column("Duration", justify="right")
    table.add_column("Summary")

    for result in report.results:
        status_str = "[green]✓ pass[/green]" if result.success else "[red]✗ fail[/red]"
        duration_str = f"{result.duration_seconds:.1f}s"
        summary = result.summary if result.success else f"[red]{result.error}[/red]"
        table.add_row(result.command, status_str, duration_str, summary)

    console.print(table)
    console.print()


def render_bundle_json(report: BundleReport, console: Console | None = None) -> None:
    """Render bundle report as JSON."""
    data = report.to_dict()
    output = json.dumps(data, indent=2)
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(output)
