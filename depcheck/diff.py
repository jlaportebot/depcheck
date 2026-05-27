"""Dependency diff and lockfile drift detection for depcheck.

Compares two versions of dependency files (requirements.txt, pyproject.toml, Pipfile)
or a lockfile against its manifest to detect:
- Added/removed packages
- Version changes (upgrades, downgrades, specifier changes)
- Unpinned dependencies that have drifted
- Lockfile drift (lockfile out of sync with manifest)
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.scanner import (
    discover_dependencies,
    normalize_package_name,
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements_txt,
)


try:
    from packaging.version import Version as _PackagingVersion  # noqa: F401
except ImportError:
    _PackagingVersion = None  # type: ignore[assignment,misc]


class DiffType(Enum):
    """Type of change between two dependency sets."""

    ADDED = "added"
    REMOVED = "removed"
    UPGRADED = "upgraded"
    DOWNGRADED = "downgraded"
    SPECIFIER_CHANGED = "specifier_changed"
    UNPINNED = "unpinned"
    PINNED = "pinned"
    UNCHANGED = "unchanged"


# Styles for diff types
_DIFF_STYLES: dict[DiffType, tuple[str, str]] = {
    DiffType.ADDED: ("+", "green"),
    DiffType.REMOVED: ("-", "red"),
    DiffType.UPGRADED: ("↑", "green"),
    DiffType.DOWNGRADED: ("↓", "red"),
    DiffType.SPECIFIER_CHANGED: ("~", "yellow"),
    DiffType.UNPINNED: ("⚠", "yellow"),
    DiffType.PINNED: ("✓", "green"),
    DiffType.UNCHANGED: ("=", "dim"),
}


@dataclass
class PackageDiff:
    """Difference for a single package between two dependency sets."""

    name: str
    diff_type: DiffType
    old_version: str | None = None
    new_version: str | None = None
    old_specifier: str | None = None
    new_specifier: str | None = None

    @property
    def symbol(self) -> str:
        """Get the display symbol for this diff type."""
        return _DIFF_STYLES.get(self.diff_type, ("?", "white"))[0]

    @property
    def color(self) -> str:
        """Get the display color for this diff type."""
        return _DIFF_STYLES.get(self.diff_type, ("?", "white"))[1]

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "change": self.diff_type.value,
            "old_version": self.old_version,
            "new_version": self.new_version,
            "old_specifier": self.old_specifier,
            "new_specifier": self.new_specifier,
        }


@dataclass
class DiffResult:
    """Result of comparing two dependency sets."""

    old_source: str
    new_source: str
    packages: list[PackageDiff] = field(default_factory=list)
    old_total: int = 0
    new_total: int = 0

    @property
    def added_count(self) -> int:
        return sum(1 for p in self.packages if p.diff_type == DiffType.ADDED)

    @property
    def removed_count(self) -> int:
        return sum(1 for p in self.packages if p.diff_type == DiffType.REMOVED)

    @property
    def changed_count(self) -> int:
        return sum(
            1
            for p in self.packages
            if p.diff_type
            not in (DiffType.ADDED, DiffType.REMOVED, DiffType.UNCHANGED)
        )

    @property
    def unchanged_count(self) -> int:
        return sum(1 for p in self.packages if p.diff_type == DiffType.UNCHANGED)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "old_source": self.old_source,
            "new_source": self.new_source,
            "summary": {
                "old_total": self.old_total,
                "new_total": self.new_total,
                "added": self.added_count,
                "removed": self.removed_count,
                "changed": self.changed_count,
                "unchanged": self.unchanged_count,
            },
            "packages": [p.to_dict() for p in self.packages],
        }


def parse_dependency_file(filepath: Path) -> list[ParsedDependency]:
    """Parse a dependency file based on its extension/name.

    Supports:
    - requirements.txt (and .txt files)
    - pyproject.toml
    - Pipfile

    Args:
        filepath: Path to the dependency file.

    Returns:
        List of ParsedDependency objects.
    """
    name = filepath.name.lower()

    if name == "pyproject.toml" or name.endswith(".toml"):
        return parse_pyproject_toml(filepath)
    elif name == "pipfile":
        return parse_pipfile(filepath)
    else:
        # Default to requirements.txt format
        return parse_requirements_txt(filepath)


def compare_dependencies(
    old_deps: list[ParsedDependency],
    new_deps: list[ParsedDependency],
) -> list[PackageDiff]:
    """Compare two sets of dependencies and produce a list of diffs.

    Args:
        old_deps: The old/base dependency set.
        new_deps: The new/target dependency set.

    Returns:
        List of PackageDiff objects describing all changes.
    """
    old_map: dict[str, ParsedDependency] = {d.name: d for d in old_deps}
    new_map: dict[str, ParsedDependency] = {d.name: d for d in new_deps}

    all_names = sorted(set(old_map.keys()) | set(new_map.keys()))
    diffs: list[PackageDiff] = []

    for name in all_names:
        old = old_map.get(name)
        new = new_map.get(name)

        if old is None and new is not None:
            # Package was added
            diffs.append(
                PackageDiff(
                    name=name,
                    diff_type=DiffType.ADDED,
                    new_version=new.version,
                    new_specifier=new.specifier,
                )
            )
        elif old is not None and new is None:
            # Package was removed
            diffs.append(
                PackageDiff(
                    name=name,
                    diff_type=DiffType.REMOVED,
                    old_version=old.version,
                    old_specifier=old.specifier,
                )
            )
        elif old is not None and new is not None:
            # Package exists in both — check for changes
            diff = _compare_versions(name, old, new)
            diffs.append(diff)

    return diffs


def _compare_versions(name: str, old: ParsedDependency, new: ParsedDependency) -> PackageDiff:
    """Compare two versions of the same package.

    Args:
        name: Normalized package name.
        old: Old dependency info.
        new: New dependency info.

    Returns:
        A PackageDiff describing the change.
    """
    old_ver = old.version
    new_ver = new.version
    old_spec = old.specifier
    new_spec = new.specifier

    # Both have no version info — unchanged
    if old_ver is None and new_ver is None and old_spec == new_spec:
        return PackageDiff(name=name, diff_type=DiffType.UNCHANGED)

    # Both have exact versions — compare them
    if old_ver and new_ver:
        if old_ver == new_ver and old_spec == new_spec:
            return PackageDiff(
                name=name,
                diff_type=DiffType.UNCHANGED,
                old_version=old_ver,
                new_version=new_ver,
                old_specifier=old_spec,
                new_specifier=new_spec,
            )
        try:
            if _PackagingVersion is None:
                raise ImportError("packaging not available")
            old_v = _PackagingVersion(old_ver)
            new_v = _PackagingVersion(new_ver)
            if new_v > old_v:
                return PackageDiff(
                    name=name,
                    diff_type=DiffType.UPGRADED,
                    old_version=old_ver,
                    new_version=new_ver,
                    old_specifier=old_spec,
                    new_specifier=new_spec,
                )
            elif new_v < old_v:
                return PackageDiff(
                    name=name,
                    diff_type=DiffType.DOWNGRADED,
                    old_version=old_ver,
                    new_version=new_ver,
                    old_specifier=old_spec,
                    new_specifier=new_spec,
                )
            else:
                # Same version, but specifier changed
                return PackageDiff(
                    name=name,
                    diff_type=DiffType.SPECIFIER_CHANGED,
                    old_version=old_ver,
                    new_version=new_ver,
                    old_specifier=old_spec,
                    new_specifier=new_spec,
                )
        except Exception:
            # Fallback to string comparison
            if old_ver != new_ver:
                diff_type = (
                    DiffType.UPGRADED
                    if old_ver < new_ver
                    else DiffType.DOWNGRADED
                )
                return PackageDiff(
                    name=name,
                    diff_type=diff_type,
                    old_version=old_ver,
                    new_version=new_ver,
                    old_specifier=old_spec,
                    new_specifier=new_spec,
                )

    # Version went from pinned to unpinned (or vice versa)
    if old_ver and not new_ver:
        if new_spec:
            return PackageDiff(
                name=name,
                diff_type=DiffType.UNPINNED,
                old_version=old_ver,
                new_version=new_ver,
                old_specifier=old_spec,
                new_specifier=new_spec,
            )
        return PackageDiff(
            name=name,
            diff_type=DiffType.UNPINNED,
            old_version=old_ver,
            new_version=new_ver,
            old_specifier=old_spec,
            new_specifier=new_spec,
        )

    if not old_ver and new_ver:
        return PackageDiff(
            name=name,
            diff_type=DiffType.PINNED,
            old_version=old_ver,
            new_version=new_ver,
            old_specifier=old_spec,
            new_specifier=new_spec,
        )

    # Specifier changed without exact version
    if old_spec != new_spec:
        return PackageDiff(
            name=name,
            diff_type=DiffType.SPECIFIER_CHANGED,
            old_version=old_ver,
            new_version=new_ver,
            old_specifier=old_spec,
            new_specifier=new_spec,
        )

    return PackageDiff(name=name, diff_type=DiffType.UNCHANGED)


def diff_files(
    old_path: str | Path,
    new_path: str | Path,
) -> DiffResult:
    """Compare two dependency files and return the diff.

    Args:
        old_path: Path to the old/base dependency file.
        new_path: Path to the new/target dependency file.

    Returns:
        DiffResult with all changes.
    """
    old_path = Path(old_path).resolve()
    new_path = Path(new_path).resolve()

    if not old_path.is_file():
        return DiffResult(
            old_source=str(old_path),
            new_source=str(new_path),
            packages=[],
        )

    if not new_path.is_file():
        return DiffResult(
            old_source=str(old_path),
            new_source=str(new_path),
            packages=[],
        )

    old_deps = parse_dependency_file(old_path)
    new_deps = parse_dependency_file(new_path)

    diffs = compare_dependencies(old_deps, new_deps)

    return DiffResult(
        old_source=str(old_path),
        new_source=str(new_path),
        packages=diffs,
        old_total=len(old_deps),
        new_total=len(new_deps),
    )


def diff_directories(
    old_dir: str | Path,
    new_dir: str | Path,
) -> DiffResult:
    """Compare dependencies between two project directories.

    Discovers dependencies from both directories and compares them.

    Args:
        old_dir: Path to the old/base project directory.
        new_dir: Path to the new/target project directory.

    Returns:
        DiffResult with all changes.
    """
    old_dir = Path(old_dir).resolve()
    new_dir = Path(new_dir).resolve()

    if not old_dir.is_dir() or not new_dir.is_dir():
        return DiffResult(
            old_source=str(old_dir),
            new_source=str(new_dir),
            packages=[],
        )

    old_deps, _ = discover_dependencies(old_dir)
    new_deps, _ = discover_dependencies(new_dir)

    diffs = compare_dependencies(old_deps, new_deps)

    return DiffResult(
        old_source=str(old_dir),
        new_source=str(new_dir),
        packages=diffs,
        old_total=len(old_deps),
        new_total=len(new_deps),
    )


def generate_unified_diff(
    old_path: str | Path,
    new_path: str | Path,
) -> str:
    """Generate a unified diff between two dependency files.

    This produces a traditional unified diff format suitable for
    display in code review tools or CI output.

    Args:
        old_path: Path to the old/base dependency file.
        new_path: Path to the new/target dependency file.

    Returns:
        Unified diff string.
    """
    old_path = Path(old_path).resolve()
    new_path = Path(new_path).resolve()

    try:
        old_lines = old_path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError):
        old_lines = []

    try:
        new_lines = new_path.read_text(encoding="utf-8").splitlines(keepends=True)
    except (OSError, UnicodeDecodeError):
        new_lines = []

    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        fromfile=str(old_path),
        tofile=str(new_path),
    )

    return "".join(diff)


def detect_lockfile_drift(
    manifest_path: str | Path,
    lockfile_path: str | Path,
) -> DiffResult:
    """Detect drift between a manifest file and its lockfile.

    Checks if the lockfile is out of sync with the manifest by comparing
    pinned versions in the lockfile against the specifiers in the manifest.

    Supports:
    - requirements.txt → requirements.lock
    - pyproject.toml → poetry.lock / pdm.lock

    Args:
        manifest_path: Path to the manifest (requirements.txt or pyproject.toml).
        lockfile_path: Path to the lockfile.

    Returns:
        DiffResult describing the drift (only shows changed/added/removed packages).
    """
    manifest_path = Path(manifest_path).resolve()
    lockfile_path = Path(lockfile_path).resolve()

    if not manifest_path.is_file() or not lockfile_path.is_file():
        return DiffResult(
            old_source=str(manifest_path),
            new_source=str(lockfile_path),
        )

    manifest_deps = parse_dependency_file(manifest_path)
    lockfile_deps = parse_dependency_file(lockfile_path)

    diffs = compare_dependencies(manifest_deps, lockfile_deps)

    # Filter to only show changes (not unchanged packages)
    changed = [d for d in diffs if d.diff_type != DiffType.UNCHANGED]

    return DiffResult(
        old_source=str(manifest_path),
        new_source=str(lockfile_path),
        packages=changed,
        old_total=len(manifest_deps),
        new_total=len(lockfile_deps),
    )


def render_diff_table(result: DiffResult, console: Console | None = None) -> None:
    """Render a diff result as a Rich table.

    Args:
        result: The diff result to render.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    console.print()
    console.print(
        Panel(
            f"[bold]depcheck diff[/bold]\n"
            f"[dim]Old: {result.old_source}[/dim]\n"
            f"[dim]New: {result.new_source}[/dim]",
            border_style="blue",
        )
    )

    if not result.packages:
        console.print("[green]No differences found.[/green]")
        return

    # Filter out unchanged for cleaner display unless all are unchanged
    changed = [p for p in result.packages if p.diff_type != DiffType.UNCHANGED]
    if not changed:
        console.print(f"[green]All {result.unchanged_count} packages unchanged.[/green]")
        return

    table = Table(
        title="Dependency Changes",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        expand=True,
    )

    table.add_column("Change", width=3, justify="center")
    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Old Version", min_width=15)
    table.add_column("New Version", min_width=15)
    table.add_column("Specifier Change", min_width=25)

    for pkg in result.packages:
        if pkg.diff_type == DiffType.UNCHANGED:
            continue

        symbol, color = _DIFF_STYLES.get(pkg.diff_type, ("?", "white"))

        old_ver = pkg.old_version or "—" if pkg.diff_type != DiffType.ADDED else ""
        new_ver = pkg.new_version or "—" if pkg.diff_type != DiffType.REMOVED else ""

        # Build specifier change string
        spec_change = ""
        if pkg.old_specifier and pkg.new_specifier and pkg.old_specifier != pkg.new_specifier:
            spec_change = f"[dim]{pkg.old_specifier}[/dim] → [yellow]{pkg.new_specifier}[/yellow]"
        elif pkg.old_specifier and not pkg.new_specifier:
            spec_change = f"[dim]{pkg.old_specifier}[/dim] → [yellow](none)[/yellow]"
        elif not pkg.old_specifier and pkg.new_specifier:
            spec_change = f"[dim](none)[/dim] → [yellow]{pkg.new_specifier}[/yellow]"

        table.add_row(
            f"[{color}]{symbol}[/{color}]",
            f"[{color}]{pkg.name}[/{color}]",
            old_ver,
            new_ver,
            spec_change,
        )

    console.print(table)

    # Summary
    console.print()
    summary_parts: list[str] = []
    summary_parts.append(f"[bold]Old: {result.old_total} deps → New: {result.new_total} deps[/bold]")
    if result.added_count:
        summary_parts.append(f"[green]+{result.added_count} added[/green]")
    if result.removed_count:
        summary_parts.append(f"[red]-{result.removed_count} removed[/red]")
    if result.changed_count:
        summary_parts.append(f"[yellow]~{result.changed_count} changed[/yellow]")
    if result.unchanged_count:
        summary_parts.append(f"[dim]={result.unchanged_count} unchanged[/dim]")

    console.print(Panel("\n".join(summary_parts), title="Diff Summary", border_style="blue"))
    console.print()


def render_diff_json(result: DiffResult, console: Console | None = None) -> None:
    """Render diff results as JSON.

    Args:
        result: The diff result to render.
        console: Optional Rich console.
    """
    import json

    if console is None:
        console = Console()

    data = result.to_dict()
    clean_console = Console(
        file=console.file,
        force_terminal=False,
        no_color=True,
        legacy_windows=False,
    )
    clean_console.print(json.dumps(data, indent=2))
