"""File-watcher daemon for continuous dependency monitoring.

Watches a Python project directory for changes to dependency files
(requirements.txt, pyproject.toml, Pipfile, Pipfile.lock) and
automatically re-scans when modifications are detected.

Features:
- Debounced scanning (avoids duplicate scans on rapid file changes)
- Health status change detection with diff alerts
- Configurable scan intervals and file patterns
- Live dashboard with Rich panel output
- Exit-on-issue mode for CI guard duty
"""

from __future__ import annotations

import datetime
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from depcheck.models import HealthStatus, ScanResult
from depcheck.scanner import scan_project

try:
    from depcheck.licenses import LicenseCategory
except ImportError:
    LicenseCategory = None  # type: ignore[assignment,misc]

# --- Default watched file patterns ---
DEFAULT_WATCH_PATTERNS: list[str] = [
    "requirements.txt",
    "requirements*.txt",  # requirements-dev.txt, requirements-test.txt
    "pyproject.toml",
    "Pipfile",
    "Pipfile.lock",
    "setup.cfg",
    "setup.py",
    "poetry.lock",
    "pdm.lock",
    "uv.lock",
]

# --- Configuration ---


@dataclass
class WatchConfig:
    """Configuration for the watch daemon.

    Attributes:
        project_path: Path to the project directory.
        debounce_seconds: Minimum time between scans after a file change.
        poll_interval: Seconds between polling checks (fallback mode).
        watch_patterns: Glob patterns for files to watch.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: Allowed license categories.
        denied_licenses: Denied SPDX license IDs.
        exit_on_issue: Exit with code 1 if any issues are found.
        fail_on: Issue type to fail on (vulnerable, outdated, unmaintained, license, any).
        show_history: Show scan history in the dashboard.
        max_history: Maximum number of historical scans to keep.
    """

    project_path: str = "."
    debounce_seconds: float = 2.0
    poll_interval: float = 1.0
    watch_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_WATCH_PATTERNS))
    check_vulnerabilities: bool = True
    check_licenses: bool = False
    allowed_license_categories: list[Any] | None = None
    denied_licenses: list[str] | None = None
    exit_on_issue: bool = False
    fail_on: str | None = None
    show_history: bool = True
    max_history: int = 20


# --- Data models ---


@dataclass
class ScanRecord:
    """Record of a single scan event."""

    timestamp: datetime.datetime
    trigger: str  # "initial", "file_change", "manual"
    trigger_file: str = ""
    duration_seconds: float = 0.0
    total_packages: int = 0
    issues_count: int = 0
    status_changes: list[StatusChange] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "trigger": self.trigger,
            "trigger_file": self.trigger_file,
            "duration_seconds": round(self.duration_seconds, 2),
            "total_packages": self.total_packages,
            "issues_count": self.issues_count,
            "status_changes": [sc.to_dict() for sc in self.status_changes],
        }


@dataclass
class StatusChange:
    """A detected change in a package's health status between scans."""

    package_name: str
    old_status: str
    new_status: str
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package_name,
            "old_status": self.old_status,
            "new_status": self.new_status,
            "details": self.details,
        }

    @property
    def is_worsening(self) -> bool:
        """Check if the change represents a worsening condition."""
        severity = {
            "healthy": 0,
            "outdated": 1,
            "unmaintained": 2,
            "yanked": 3,
            "vulnerable": 4,
            "removed": 5,
            "unknown": -1,
        }
        return severity.get(self.new_status, -1) > severity.get(self.old_status, -1)

    @property
    def is_improvement(self) -> bool:
        """Check if the change represents an improvement."""
        return not self.is_worsening and self.old_status != self.new_status


@dataclass
class WatchState:
    """State of the watch daemon."""

    config: WatchConfig
    last_scan_result: ScanResult | None = None
    last_scan_time: float = 0.0
    scan_history: list[ScanRecord] = field(default_factory=list)
    file_mtimes: dict[str, float] = field(default_factory=dict)
    watched_files: list[str] = field(default_factory=list)
    total_scans: int = 0
    total_changes_detected: int = 0
    start_time: float = field(default_factory=time.time)
    is_running: bool = True
    last_trigger: str = "none"


# --- File watching ---


def discover_watched_files(project_path: Path, patterns: list[str]) -> list[Path]:
    """Find all files matching the watch patterns in the project directory.

    Args:
        project_path: Path to the project directory.
        patterns: Glob patterns to match.

    Returns:
        List of Path objects for matching files.
    """
    matched: list[Path] = []
    for pattern in patterns:
        # Match directly in the project root
        for path in project_path.glob(pattern):
            if path.is_file():
                matched.append(path)
    return sorted(set(matched))


def get_file_mtimes(files: list[Path]) -> dict[str, float]:
    """Get modification times for a list of files.

    Args:
        files: List of file paths.

    Returns:
        Dict mapping file path strings to their mtime.
    """
    mtimes: dict[str, float] = {}
    for f in files:
        try:
            mtimes[str(f)] = f.stat().st_mtime
        except OSError:
            pass
    return mtimes


def detect_changes(old_mtimes: dict[str, float], new_mtimes: dict[str, float]) -> list[str]:
    """Detect which files have changed between two mtime snapshots.

    Args:
        old_mtimes: Previous modification times.
        new_mtimes: Current modification times.

    Returns:
        List of file paths that changed (modified or newly created).
    """
    changed: list[str] = []

    # Check for modified files
    for path, mtime in new_mtimes.items():
        if path not in old_mtimes:
            changed.append(path)  # New file
        elif mtime > old_mtimes[path]:
            changed.append(path)  # Modified file

    # Check for deleted files
    for path in old_mtimes:
        if path not in new_mtimes:
            changed.append(path)  # Deleted file

    return changed


# --- Status diff ---


def diff_scan_results(old: ScanResult, new: ScanResult) -> list[StatusChange]:
    """Compare two scan results and detect status changes.

    Args:
        old: Previous scan result.
        new: Current scan result.

    Returns:
        List of StatusChange objects for packages whose status changed.
    """
    changes: list[StatusChange] = []

    old_statuses: dict[str, str] = {p.name: p.status.value for p in old.packages}
    new_statuses: dict[str, str] = {p.name: p.status.value for p in new.packages}

    # Check for status changes in existing packages
    for name, new_status in new_statuses.items():
        old_status = old_statuses.get(name)
        if old_status is None:
            changes.append(
                StatusChange(
                    package_name=name,
                    old_status="(new)",
                    new_status=new_status,
                    details="Package added to dependencies",
                )
            )
        elif old_status != new_status:
            # Build details about the change
            details = _build_change_details(name, old, new)
            changes.append(
                StatusChange(
                    package_name=name,
                    old_status=old_status,
                    new_status=new_status,
                    details=details,
                )
            )

    # Check for removed packages
    for name, old_status in old_statuses.items():
        if name not in new_statuses:
            changes.append(
                StatusChange(
                    package_name=name,
                    old_status=old_status,
                    new_status="(removed)",
                    details="Package removed from dependencies",
                )
            )

    return changes


def _build_change_details(name: str, old: ScanResult, new: ScanResult) -> str:
    """Build a human-readable detail string for a status change."""
    old_pkg = next((p for p in old.packages if p.name == name), None)
    new_pkg = next((p for p in new.packages if p.name == name), None)

    parts: list[str] = []
    if old_pkg and new_pkg:
        if old_pkg.installed_version != new_pkg.installed_version:
            parts.append(f"version: {old_pkg.installed_version} → {new_pkg.installed_version}")
        if old_pkg.latest_version != new_pkg.latest_version:
            parts.append(f"latest: {old_pkg.latest_version} → {new_pkg.latest_version}")
        old_vuln_count = len(old_pkg.vulnerabilities)
        new_vuln_count = len(new_pkg.vulnerabilities)
        if old_vuln_count != new_vuln_count:
            parts.append(f"vulnerabilities: {old_vuln_count} → {new_vuln_count}")

    return "; ".join(parts) if parts else ""


# --- Scanning ---


def run_scan(
    config: WatchConfig, trigger: str, trigger_file: str = ""
) -> tuple[ScanResult, ScanRecord]:
    """Run a dependency scan and record the result.

    Args:
        config: Watch configuration.
        trigger: What triggered this scan.
        trigger_file: File that triggered the scan (if applicable).

    Returns:
        Tuple of (scan result, scan record).
    """
    start = time.time()

    result = scan_project(
        project_path=config.project_path,
        check_vulnerabilities=config.check_vulnerabilities,
        check_licenses=config.check_licenses,
        allowed_license_categories=config.allowed_license_categories,
        denied_licenses=config.denied_licenses,
    )

    duration = time.time() - start
    issues = sum(
        1 for p in result.packages if p.status not in (HealthStatus.HEALTHY, HealthStatus.UNKNOWN)
    )

    record = ScanRecord(
        timestamp=datetime.datetime.now(),
        trigger=trigger,
        trigger_file=trigger_file,
        duration_seconds=duration,
        total_packages=result.total,
        issues_count=issues,
    )

    return result, record


# --- Rich rendering ---


def render_watch_dashboard(state: WatchState, changed_files: list[str] | None = None) -> Panel:
    """Render the live watch dashboard.

    Args:
        state: Current watch state.
        changed_files: Files that changed (if any).

    Returns:
        Rich Panel with the dashboard content.
    """
    elapsed = time.time() - state.start_time
    hours, remainder = divmod(int(elapsed), 3600)
    minutes, seconds = divmod(remainder, 60)
    uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    # Build main table
    table = Table(show_header=False, show_edge=False, pad_edge=False, expand=True)
    table.add_column("key", style="dim", width=18)
    table.add_column("value")

    table.add_row("Uptime", uptime_str)
    table.add_row("Total Scans", str(state.total_scans))
    table.add_row("Changes Detected", str(state.total_changes_detected))
    table.add_row("Watched Files", str(len(state.watched_files)))
    table.add_row("Last Trigger", state.last_trigger)

    # Current scan summary
    result = state.last_scan_result
    if result:
        table.add_row("─" * 18, "─" * 40)
        table.add_row("Project", result.project_path)
        table.add_row("Packages", str(result.total))
        table.add_row("Healthy", f"[green]{result.healthy_count}[/green]")
        if result.outdated_count:
            table.add_row("Outdated", f"[yellow]{result.outdated_count}[/yellow]")
        if result.vulnerable_count:
            table.add_row("Vulnerable", f"[red bold]{result.vulnerable_count}[/red bold]")
        if result.unmaintained_count:
            table.add_row("Unmaintained", f"[yellow]{result.unmaintained_count}[/yellow]")
        if result.yanked_count:
            table.add_row("Yanked", f"[red]{result.yanked_count}[/red]")
        if result.removed_count:
            table.add_row("Removed", f"[red]{result.removed_count}[/red]")
        if result.license_issues_count:
            table.add_row("License Issues", f"[orange1]{result.license_issues_count}[/orange1]")

    # Changed files alert
    if changed_files:
        table.add_row("─" * 18, "─" * 40)
        file_list = "\n".join(f"  • {Path(f).name}" for f in changed_files)
        table.add_row("[bold red]Changed Files[/bold red]", file_list)

    # Status changes from last scan
    if state.scan_history and state.scan_history[-1].status_changes:
        table.add_row("─" * 18, "─" * 40)
        change_lines: list[str] = []
        for sc in state.scan_history[-1].status_changes:
            if sc.is_worsening:
                icon = "🔺"
                style = "red"
            elif sc.is_improvement:
                icon = "🔻"
                style = "green"
            else:
                icon = "🔄"
                style = "yellow"
            line = f"{icon} {sc.package_name}: {sc.old_status} → {sc.new_status}"
            if sc.details:
                line += f" ({sc.details})"
            change_lines.append(f"[{style}]{line}[/{style}]")
        table.add_row(
            "Status Changes",
            "\n".join(change_lines[:8]),  # Limit to 8 changes shown
        )

    # History (last 5 scans)
    if state.config.show_history and len(state.scan_history) > 1:
        table.add_row("─" * 18, "─" * 40)
        history_lines: list[str] = []
        for record in state.scan_history[-5:]:
            ts = record.timestamp.strftime("%H:%M:%S")
            trigger_icon = (
                "📄"
                if record.trigger == "file_change"
                else "🚀"
                if record.trigger == "initial"
                else "🔄"
            )
            history_lines.append(
                f"{trigger_icon} {ts} — {record.total_packages} pkgs, "
                f"{record.issues_count} issues ({record.duration_seconds:.1f}s)"
            )
        table.add_row("Scan History", "\n".join(history_lines))

    subtitle = Text("Press Ctrl+C to stop", style="dim italic")
    return Panel(
        table,
        title="[bold]depcheck watch[/bold] 👁",
        subtitle=subtitle,
        border_style="blue",
        padding=(1, 2),
    )


def render_change_alert(changes: list[StatusChange]) -> Panel | None:
    """Render an alert panel for detected status changes.

    Args:
        changes: List of detected status changes.

    Returns:
        Rich Panel with alert details, or None if no concerning changes.
    """
    worsening = [c for c in changes if c.is_worsening]
    if not worsening:
        return None

    content_parts: list[str] = []
    for change in worsening:
        name = change.package_name
        line = (
            f"[bold red]{name}[/bold red]: "
            f"{change.old_status} → [bold red]{change.new_status}[/bold red]"
        )
        if change.details:
            line += f"\n  {change.details}"
        content_parts.append(line)

    return Panel(
        "\n\n".join(content_parts),
        title="[bold red]⚠ Health Status Worsened[/bold red]",
        border_style="red",
        padding=(1, 2),
    )


# --- Main watch loop ---


def watch_loop(config: WatchConfig, console: Console | None = None) -> None:
    """Main watch loop that monitors files and re-scans on changes.

    Args:
        config: Watch configuration.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    state = WatchState(config=config)
    project_path = Path(config.project_path).resolve()

    # Discover watched files
    watched = discover_watched_files(project_path, config.watch_patterns)
    state.watched_files = [str(f) for f in watched]
    state.file_mtimes = get_file_mtimes(watched)

    if not watched:
        console.print("[red]No dependency files found to watch.[/red]")
        console.print(f"[dim]Looked in: {project_path}[/dim]")
        console.print(f"[dim]Patterns: {', '.join(config.watch_patterns)}[/dim]")
        sys.exit(1)

    console.print(
        f"[bold]depcheck watch[/bold] — Monitoring {len(watched)} file(s) in {project_path}"
    )
    for f in watched:
        console.print(f"  [dim]• {f.relative_to(project_path)}[/dim]")
    console.print()

    # Initial scan
    result, record = run_scan(config, trigger="initial")
    state.last_scan_result = result
    state.last_scan_time = time.time()
    state.total_scans = 1
    state.last_trigger = "initial"
    state.scan_history.append(record)
    if len(state.scan_history) > config.max_history:
        state.scan_history = state.scan_history[-config.max_history :]

    # Check exit-on-issue for initial scan
    if config.exit_on_issue:
        if _should_exit_on_issue(result, config.fail_on):
            console.print(render_watch_dashboard(state))
            alert = render_change_alert(record.status_changes)
            if alert:
                console.print(alert)
            _render_scan_issues(result, console)
            sys.exit(1)

    # Main loop with Live display
    try:
        with Live(
            render_watch_dashboard(state),
            console=console,
            refresh_per_second=1,
            vertical_overflow="visible",
        ) as live:
            while state.is_running:
                time.sleep(config.poll_interval)

                # Re-discover files (in case new ones were added)
                watched = discover_watched_files(project_path, config.watch_patterns)
                state.watched_files = [str(f) for f in watched]
                new_mtimes = get_file_mtimes(watched)

                # Detect changes
                changed = detect_changes(state.file_mtimes, new_mtimes)
                state.file_mtimes = new_mtimes

                if changed:
                    # Debounce: wait for changes to settle
                    time.sleep(config.debounce_seconds)

                    # Re-check mtimes after debounce
                    final_mtimes = get_file_mtimes(watched)
                    state.file_mtimes = final_mtimes

                    # Run scan
                    trigger_file = changed[0] if changed else ""
                    result, record = run_scan(
                        config, trigger="file_change", trigger_file=trigger_file
                    )

                    # Compute status diff
                    if state.last_scan_result is not None:
                        changes = diff_scan_results(state.last_scan_result, result)
                        record.status_changes = changes

                        # Show alerts for worsening conditions
                        worsening = [c for c in changes if c.is_worsening]
                        if worsening:
                            alert = render_change_alert(changes)
                            if alert:
                                live.update(alert, refresh=True)

                    state.last_scan_result = result
                    state.last_scan_time = time.time()
                    state.total_scans += 1
                    state.total_changes_detected += 1
                    state.last_trigger = "file_change"
                    state.scan_history.append(record)
                    if len(state.scan_history) > config.max_history:
                        state.scan_history = state.scan_history[-config.max_history :]

                    # Check exit-on-issue
                    if config.exit_on_issue:
                        if _should_exit_on_issue(result, config.fail_on):
                            live.update(render_watch_dashboard(state, changed_files=changed))
                            _render_scan_issues(result, console)
                            sys.exit(1)

                # Update dashboard
                live.update(
                    render_watch_dashboard(state, changed_files=changed if changed else None)
                )

    except KeyboardInterrupt:
        state.is_running = False
        console.print()
        console.print("[bold]depcheck watch[/bold] stopped.")
        _render_summary(state, console)


def _should_exit_on_issue(result: ScanResult, fail_on: str | None) -> bool:
    """Check if the scan result should trigger an exit-on-issue.

    Args:
        result: Scan result to check.
        fail_on: Issue type to fail on.

    Returns:
        True if the exit condition is met.
    """
    if fail_on is None or fail_on == "any":
        return result.has_issues()
    elif fail_on == "vulnerable":
        return result.vulnerable_count > 0
    elif fail_on == "outdated":
        return result.outdated_count > 0
    elif fail_on == "unmaintained":
        return result.unmaintained_count > 0
    elif fail_on == "license":
        return result.license_issues_count > 0
    return False


def _render_scan_issues(result: ScanResult, console: Console) -> None:
    """Render a table of all issues found in the scan."""
    issue_packages = [
        p for p in result.packages if p.status not in (HealthStatus.HEALTHY, HealthStatus.UNKNOWN)
    ]
    if not issue_packages:
        return

    table = Table(title="Issues Found", show_lines=True)
    table.add_column("Package", style="bold")
    table.add_column("Status")
    table.add_column("Version")
    table.add_column("Latest")
    table.add_column("Details")

    for pkg in issue_packages:
        status_style = _get_status_style(pkg.status)
        details = ""
        if pkg.vulnerabilities:
            details = f"{len(pkg.vulnerabilities)} vulnerability(ies)"
        elif pkg.has_license_issue and pkg.license_info:
            details = pkg.license_info.compliance_note
        elif pkg.is_yanked:
            details = "Version yanked from PyPI"
        elif pkg.is_removed:
            details = "Package removed from PyPI"

        table.add_row(
            pkg.name,
            f"[{status_style}]{pkg.status.value}[/{status_style}]",
            pkg.installed_version,
            pkg.latest_version or "—",
            details,
        )

    console.print(table)


def _get_status_style(status: HealthStatus) -> str:
    """Get Rich style string for a health status."""
    styles = {
        HealthStatus.HEALTHY: "green",
        HealthStatus.OUTDATED: "yellow",
        HealthStatus.VULNERABLE: "red bold",
        HealthStatus.UNMAINTAINED: "yellow",
        HealthStatus.YANKED: "red",
        HealthStatus.REMOVED: "red",
        HealthStatus.UNKNOWN: "dim",
    }
    return styles.get(status, "white")


def _render_summary(state: WatchState, console: Console) -> None:
    """Render a final summary when the watch daemon stops."""
    elapsed = time.time() - state.start_time
    hours, remainder = divmod(int(elapsed), 3600)
    minutes, seconds = divmod(remainder, 60)

    console.print(f"[dim]Uptime: {hours:02d}:{minutes:02d}:{seconds:02d}[/dim]")
    console.print(f"[dim]Total scans: {state.total_scans}[/dim]")
    console.print(f"[dim]Changes detected: {state.total_changes_detected}[/dim]")

    if state.scan_history:
        last = state.scan_history[-1]
        console.print(
            f"[dim]Last scan: {last.timestamp.strftime('%H:%M:%S')} — "
            f"{last.total_packages} packages, {last.issues_count} issues[/dim]"
        )

    # Show all status changes across the entire session
    all_changes: list[StatusChange] = []
    for record in state.scan_history:
        all_changes.extend(record.status_changes)

    if all_changes:
        console.print()
        console.print("[bold]All status changes this session:[/bold]")
        for change in all_changes:
            if change.is_worsening:
                icon = "🔺"
                style = "red"
            elif change.is_improvement:
                icon = "🔻"
                style = "green"
            else:
                icon = "🔄"
                style = "yellow"
            console.print(
                f"  {icon} [{style}]{change.package_name}: "
                f"{change.old_status} → {change.new_status}[/{style}]"
            )
