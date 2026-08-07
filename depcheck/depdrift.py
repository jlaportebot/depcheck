"""Dependency drift tracker for Python projects.

Tracks how dependencies change over time by comparing dependency files
at different points (e.g., git commits, tags). Detects:
- Version drift (packages falling behind latest)
- Dependency additions/removals over time
- Version pin erosion (loosening constraints)
- Drift velocity (how fast dependencies are changing)
- High-drift packages needing attention
"""

from __future__ import annotations

import datetime
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.scanner import (
    parse_pyproject_toml,
    parse_requirements_txt,
)


@dataclass
class DriftEntry:
    """A single drift event for a package."""

    name: str
    old_version: str | None = None
    new_version: str | None = None
    old_specifier: str | None = None
    new_specifier: str | None = None
    change_type: str = ""  # added, removed, upgraded, downgraded, pinned, unpinned
    drift_days: int | None = None
    commit: str | None = None
    date: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_specifier": self.old_specifier,
            "new_specifier": self.new_specifier,
            "change_type": self.change_type,
            "drift_days": self.drift_days,
            "commit": self.commit,
            "date": self.date,
        }


@dataclass
class DriftSnapshot:
    """A snapshot of dependencies at a point in time."""

    commit: str
    date: str
    dependencies: dict[str, ParsedDependency] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "commit": self.commit,
            "date": self.date,
            "dependencies": {
                name: {"version": dep.version, "specifier": dep.specifier}
                for name, dep in self.dependencies.items()
            },
        }


@dataclass
class DriftReport:
    """Aggregated drift analysis report."""

    entries: list[DriftEntry] = field(default_factory=list)
    snapshots_compared: int = 0
    from_date: str | None = None
    to_date: str | None = None
    from_commit: str | None = None
    to_commit: str | None = None
    added_count: int = 0
    removed_count: int = 0
    upgraded_count: int = 0
    downgraded_count: int = 0
    pinned_count: int = 0
    unpinned_count: int = 0
    unchanged_count: int = 0
    high_drift_packages: list[str] = field(default_factory=list)
    drift_velocity: float = 0.0  # changes per week
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "snapshots_compared": self.snapshots_compared,
                "from_date": self.from_date,
                "to_date": self.to_date,
                "from_commit": self.from_commit,
                "to_commit": self.to_commit,
                "added": self.added_count,
                "removed": self.removed_count,
                "upgraded": self.upgraded_count,
                "downgraded": self.downgraded_count,
                "pinned": self.pinned_count,
                "unpinned": self.unpinned_count,
                "unchanged": self.unchanged_count,
                "high_drift_packages": self.high_drift_packages,
                "drift_velocity": round(self.drift_velocity, 2),
            },
            "entries": [e.to_dict() for e in self.entries],
            "errors": self.errors,
        }


def get_git_commits(
    project_path: Path,
    count: int = 10,
    file_path: str | None = None,
) -> list[tuple[str, str]]:
    """Get recent git commits that modified dependency files.

    Args:
        project_path: Path to the git project.
        count: Maximum number of commits to return.
        file_path: Optional specific file to track.

    Returns:
        List of (commit_hash, date_string) tuples, newest first.
    """
    try:
        # Build the git log command
        cmd = ["git", "-C", str(project_path), "log", f"-{count}", "--format=%H %cs"]

        if file_path:
            cmd.extend(["--", file_path])
        else:
            # Track all common dependency files
            cmd.extend(["--", "requirements.txt", "pyproject.toml", "Pipfile", "Pipfile.lock"])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode != 0:
            return []

        commits: list[tuple[str, str]] = []
        for line in result.stdout.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                commits.append((parts[0], parts[1]))

        return commits

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []


def get_file_at_commit(
    project_path: Path,
    commit: str,
    file_path: str,
) -> str | None:
    """Get the content of a file at a specific git commit.

    Args:
        project_path: Path to the git project.
        commit: The commit hash.
        file_path: Relative path to the file.

    Returns:
        File content string, or None if not found.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(project_path), "show", f"{commit}:{file_path}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def capture_snapshot(
    project_path: Path,
    commit: str,
    date: str,
) -> DriftSnapshot:
    """Capture a dependency snapshot at a specific git commit.

    Args:
        project_path: Path to the git project.
        commit: The commit hash.
        date: The commit date string.

    Returns:
        A DriftSnapshot with all dependencies at that commit.
    """
    snapshot = DriftSnapshot(commit=commit, date=date)
    deps: list[ParsedDependency] = []

    # Try requirements.txt
    content = get_file_at_commit(project_path, commit, "requirements.txt")
    if content:
        # Write to temp file for parsing
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(content)
            f.flush()
            deps.extend(parse_requirements_txt(Path(f.name)))

    # Try pyproject.toml
    content = get_file_at_commit(project_path, commit, "pyproject.toml")
    if content:
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            deps.extend(parse_pyproject_toml(Path(f.name)))

    for dep in deps:
        snapshot.dependencies[dep.name] = dep

    return snapshot


def compare_snapshots(
    old: DriftSnapshot,
    new: DriftSnapshot,
) -> list[DriftEntry]:
    """Compare two dependency snapshots and find drift.

    Args:
        old: The older snapshot.
        new: The newer snapshot.

    Returns:
        List of DriftEntry items describing the changes.
    """
    entries: list[DriftEntry] = []

    old_names = set(old.dependencies.keys())
    new_names = set(new.dependencies.keys())

    # Compute drift days
    drift_days = None
    if old.date and new.date:
        try:
            old_date = datetime.date.fromisoformat(old.date)
            new_date = datetime.date.fromisoformat(new.date)
            drift_days = (new_date - old_date).days
        except (ValueError, TypeError):
            pass

    # Added packages
    for name in sorted(new_names - old_names):
        dep = new.dependencies[name]
        entries.append(
            DriftEntry(
                name=name,
                new_version=dep.version,
                new_specifier=dep.specifier,
                change_type="added",
                drift_days=drift_days,
                commit=new.commit,
                date=new.date,
            )
        )

    # Removed packages
    for name in sorted(old_names - new_names):
        dep = old.dependencies[name]
        entries.append(
            DriftEntry(
                name=name,
                old_version=dep.version,
                old_specifier=dep.specifier,
                change_type="removed",
                drift_days=drift_days,
                commit=new.commit,
                date=new.date,
            )
        )

    # Changed packages
    for name in sorted(old_names & new_names):
        old_dep = old.dependencies[name]
        new_dep = new.dependencies[name]

        changes: list[str] = []

        # Version change
        if old_dep.version != new_dep.version and old_dep.version and new_dep.version:
            try:
                from packaging.version import Version

                old_ver = Version(old_dep.version)
                new_ver = Version(new_dep.version)
                if new_ver > old_ver:
                    changes.append("upgraded")
                elif new_ver < old_ver:
                    changes.append("downgraded")
                else:
                    changes.append("changed")  # Same version but different representation
            except Exception:
                changes.append("changed")
        elif old_dep.version is None and new_dep.version is not None:
            changes.append("pinned")
        elif old_dep.version is not None and new_dep.version is None:
            changes.append("unpinned")

        # Specifier change
        if old_dep.specifier != new_dep.specifier:
            if old_dep.specifier and not new_dep.specifier:
                changes.append("unpinned")
            elif not old_dep.specifier and new_dep.specifier:
                changes.append("pinned")
            elif old_dep.specifier and new_dep.specifier:
                # Check if constraint became more or less strict
                old_exact = "==" in old_dep.specifier
                new_exact = "==" in new_dep.specifier
                if old_exact and not new_exact:
                    changes.append("unpinned")
                elif not old_exact and new_exact:
                    changes.append("pinned")

        if not changes:
            continue

        change_type = changes[0] if len(changes) == 1 else "+".join(changes)

        entries.append(
            DriftEntry(
                name=name,
                old_version=old_dep.version,
                new_version=new_dep.version,
                old_specifier=old_dep.specifier,
                new_specifier=new_dep.specifier,
                change_type=change_type,
                drift_days=drift_days,
                commit=new.commit,
                date=new.date,
            )
        )

    return entries


def compute_drift_velocity(entries: list[DriftEntry], total_days: int | None) -> float:
    """Compute drift velocity (changes per week).

    Args:
        entries: List of drift entries.
        total_days: Total time span in days.

    Returns:
        Changes per week, or 0.0 if not computable.
    """
    if not total_days or total_days <= 0:
        return 0.0
    weeks = total_days / 7.0
    if weeks <= 0:
        return 0.0
    return len(entries) / weeks


def identify_high_drift_packages(
    entries: list[DriftEntry],
    threshold: int = 3,
) -> list[str]:
    """Identify packages that change frequently (high drift).

    Args:
        entries: List of drift entries.
        threshold: Minimum number of changes to be considered high drift.

    Returns:
        List of package names with high drift.
    """
    change_counts: dict[str, int] = {}
    for entry in entries:
        change_counts[entry.name] = change_counts.get(entry.name, 0) + 1

    return sorted(name for name, count in change_counts.items() if count >= threshold)


def build_drift_report(
    project_path: str | Path,
    from_commit: str | None = None,
    to_commit: str | None = None,
    max_commits: int = 20,
) -> DriftReport:
    """Build a drift report by comparing dependency snapshots over time.

    Args:
        project_path: Path to the git project.
        from_commit: Starting commit (uses oldest if None).
        to_commit: Ending commit (uses HEAD if None).
        max_commits: Max commits to scan for dependency changes.

    Returns:
        A DriftReport with drift analysis.
    """
    project_path = Path(str(project_path)).resolve()

    if not project_path.is_dir():
        return DriftReport(errors=[f"Path is not a directory: {project_path}"])

    # Get commits that modified dependency files
    commits = get_git_commits(project_path, count=max_commits)

    if len(commits) < 2:
        return DriftReport(
            errors=[
                "Need at least 2 commits with dependency file changes. "
                "Make sure this is a git repo with dependency files tracked."
            ]
        )

    # Use oldest and newest if not specified
    if from_commit is None:
        from_commit = commits[-1][0]
    if to_commit is None:
        to_commit = commits[0][0]

    # Capture snapshots
    from_date = None
    to_date = None
    for commit_hash, date in commits:
        if commit_hash == from_commit:
            from_date = date
        if commit_hash == to_commit:
            to_date = date

    old_snapshot = capture_snapshot(project_path, from_commit, from_date or "")
    new_snapshot = capture_snapshot(project_path, to_commit, to_date or "")

    # Compare
    entries = compare_snapshots(old_snapshot, new_snapshot)

    # Compute totals
    report = DriftReport(
        entries=entries,
        snapshots_compared=2,
        from_date=from_date,
        to_date=to_date,
        from_commit=from_commit[:8] if from_commit else None,
        to_commit=to_commit[:8] if to_commit else None,
    )

    for entry in entries:
        if entry.change_type == "added":
            report.added_count += 1
        elif entry.change_type == "removed":
            report.removed_count += 1
        elif entry.change_type == "upgraded":
            report.upgraded_count += 1
        elif entry.change_type == "downgraded":
            report.downgraded_count += 1
        elif entry.change_type == "pinned":
            report.pinned_count += 1
        elif entry.change_type == "unpinned":
            report.unpinned_count += 1

    # Unchanged count
    old_names = set(old_snapshot.dependencies.keys())
    new_names = set(new_snapshot.dependencies.keys())
    changed_names = {e.name for e in entries}
    report.unchanged_count = len((old_names & new_names) - changed_names)

    # Drift velocity
    total_days = None
    if from_date and to_date:
        try:
            fd = datetime.date.fromisoformat(from_date)
            td = datetime.date.fromisoformat(to_date)
            total_days = (td - fd).days
        except (ValueError, TypeError):
            pass

    report.drift_velocity = compute_drift_velocity(entries, total_days)
    report.high_drift_packages = identify_high_drift_packages(entries)

    # Sort entries by type then name
    type_order = {
        "added": 0,
        "removed": 1,
        "upgraded": 2,
        "downgraded": 3,
        "pinned": 4,
        "unpinned": 5,
    }
    report.entries.sort(key=lambda e: (type_order.get(e.change_type, 6), e.name))

    return report


def render_drift_table(report: DriftReport, console: Console | None = None) -> None:
    """Render the drift report as a Rich table.

    Args:
        report: The DriftReport to render.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    if not report.entries:
        console.print("[green]✓ No dependency drift detected between snapshots.[/green]")
        return

    # Summary
    parts: list[str] = []
    if report.added_count:
        parts.append(f"[green]+{report.added_count} added[/green]")
    if report.removed_count:
        parts.append(f"[red]-{report.removed_count} removed[/red]")
    if report.upgraded_count:
        parts.append(f"[blue]↑{report.upgraded_count} upgraded[/blue]")
    if report.downgraded_count:
        parts.append(f"[yellow]↓{report.downgraded_count} downgraded[/yellow]")
    if report.pinned_count:
        parts.append(f"[cyan]🔒{report.pinned_count} pinned[/cyan]")
    if report.unpinned_count:
        parts.append(f"[magenta]🔓{report.unpinned_count} unpinned[/magenta]")

    summary = "Drift: " + ", ".join(parts)
    summary += f" • {report.unchanged_count} unchanged"
    summary += f" • Velocity: {report.drift_velocity:.1f}/week"

    if report.from_commit and report.to_commit:
        summary += f" • {report.from_commit}..{report.to_commit}"

    console.print()
    console.print(Panel(summary, title="Dependency Drift Analysis", border_style="blue"))

    # Main table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Type", justify="center", min_width=12)
    table.add_column("Package", style="cyan", min_width=20)
    table.add_column("Old", justify="right", min_width=12)
    table.add_column("New", justify="right", min_width=12)
    table.add_column("Days", justify="right", min_width=8)
    table.add_column("Date", min_width=12)

    type_styles = {
        "added": ("green", "+ ADDED"),
        "removed": ("red", "- REMOVED"),
        "upgraded": ("blue", "↑ UPGRADE"),
        "downgraded": ("yellow", "↓ DOWNGRADE"),
        "pinned": ("cyan", "🔒 PINNED"),
        "unpinned": ("magenta", "🔓 UNPINNED"),
    }

    for entry in report.entries:
        style, icon = type_styles.get(entry.change_type, ("dim", "? UNKNOWN"))
        old_ver = entry.old_version or "-"
        new_ver = entry.new_version or "-"
        days_str = str(entry.drift_days) if entry.drift_days is not None else "-"
        date_str = entry.date or "-"

        table.add_row(
            f"[{style}]{icon}[/{style}]",
            entry.name,
            old_ver,
            f"[bold]{new_ver}[/bold]" if new_ver != "-" else new_ver,
            days_str,
            date_str,
        )

    console.print(table)

    # High drift warning
    if report.high_drift_packages:
        console.print()
        console.print(
            f"[yellow]⚠ High-drift packages (frequent changes): "
            f"{', '.join(report.high_drift_packages)}[/yellow]"
        )
        console.print("[dim]Consider pinning these packages to reduce instability.[/dim]")


def render_drift_json(report: DriftReport) -> str:
    """Render the drift report as JSON string.

    Args:
        report: The DriftReport to render.

    Returns:
        JSON string of the report.
    """
    import json

    return json.dumps(report.to_dict(), indent=2)
