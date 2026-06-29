"""Dependency budget management for depcheck.

Define a budget of allowed dependencies per category and check
whether your project stays within those limits. Budgets can be
defined in pyproject.toml under [tool.depcheck.budget] or passed
via CLI flags. Supports total budget, per-category budgets
(direct, transitive, dev, optional), and custom group budgets.
"""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.pypi import PyPIClient
from depcheck.scanner import discover_dependencies

# Package name regex (PEP 503)
_PKG_RE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)")


# ─── Data Models ───────────────────────────────────────────────────────────


@dataclass
class BudgetCategory:
    """A single budget category with its limit and current count."""

    name: str
    limit: int | None = None  # None means unlimited
    count: int = 0
    packages: list[str] = field(default_factory=list)

    @property
    def is_over(self) -> bool:
        """Whether the budget category exceeds its limit."""
        return self.limit is not None and self.count > self.limit

    @property
    def remaining(self) -> int | None:
        """Remaining slots in this budget category."""
        if self.limit is None:
            return None
        return max(0, self.limit - self.count)

    @property
    def utilization(self) -> float | None:
        """Utilization percentage (0–100+)."""
        if self.limit is None or self.limit == 0:
            return None
        return round((self.count / self.limit) * 100, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "limit": self.limit,
            "count": self.count,
            "remaining": self.remaining,
            "utilization_percent": self.utilization,
            "is_over": self.is_over,
            "packages": self.packages,
        }


@dataclass
class BudgetConfig:
    """Budget configuration loaded from pyproject.toml or CLI flags."""

    total: int | None = None
    direct: int | None = None
    transitive: int | None = None
    dev: int | None = None
    optional: int | None = None
    groups: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BudgetConfig:
        """Create BudgetConfig from a dictionary (e.g., parsed TOML)."""
        return cls(
            total=data.get("total"),
            direct=data.get("direct"),
            transitive=data.get("transitive"),
            dev=data.get("dev"),
            optional=data.get("optional"),
            groups=data.get("groups", {}),
        )

    @classmethod
    def from_pyproject(cls, project_path: Path) -> BudgetConfig | None:
        """Load budget config from [tool.depcheck.budget] in pyproject.toml."""
        pyproject = project_path / "pyproject.toml"
        if not pyproject.is_file():
            return None

        try:
            content = pyproject.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                return None

        try:
            data = tomllib.loads(content)
        except Exception:
            return None

        budget_data = data.get("tool", {}).get("depcheck", {}).get("budget")
        if budget_data is None:
            return None

        return cls.from_dict(budget_data)


@dataclass
class BudgetReport:
    """Complete budget analysis report."""

    project_path: str
    config: BudgetConfig
    categories: list[BudgetCategory] = field(default_factory=list)
    total_deps: int = 0
    total_direct: int = 0
    total_transitive: int = 0
    total_dev: int = 0
    total_optional: int = 0
    group_counts: dict[str, int] = field(default_factory=dict)
    group_packages: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def is_within_budget(self) -> bool:
        """Whether all budget categories are within limits."""
        return not any(cat.is_over for cat in self.categories)

    @property
    def over_budget_categories(self) -> list[BudgetCategory]:
        """Categories that exceed their budget."""
        return [cat for cat in self.categories if cat.is_over]

    @property
    def utilization_summary(self) -> dict[str, float | None]:
        """Utilization percentages for all categories."""
        return {cat.name: cat.utilization for cat in self.categories}

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "is_within_budget": self.is_within_budget,
            "total_deps": self.total_deps,
            "total_direct": self.total_direct,
            "total_transitive": self.total_transitive,
            "total_dev": self.total_dev,
            "total_optional": self.total_optional,
            "group_counts": self.group_counts,
            "categories": [cat.to_dict() for cat in self.categories],
            "errors": self.errors,
        }


# ─── Core Logic ────────────────────────────────────────────────────────────


def _classify_dependencies(
    project_path: Path,
) -> tuple[
    list[ParsedDependency],
    list[ParsedDependency],
    list[ParsedDependency],
    list[ParsedDependency],
]:
    """Classify dependencies into direct, dev, optional, and transitive.

    Returns:
        Tuple of (direct_deps, dev_deps, optional_deps, transitive_deps).
    """
    all_deps, _ = discover_dependencies(project_path)

    # Try to parse pyproject.toml for richer classification
    pyproject = project_path / "pyproject.toml"
    direct_deps: list[ParsedDependency] = []
    dev_deps: list[ParsedDependency] = []
    optional_deps: list[ParsedDependency] = []

    if pyproject.is_file():
        try:
            content = pyproject.read_text(encoding="utf-8")
            if sys.version_info >= (3, 11):
                import tomllib
            else:
                try:
                    import tomli as tomllib  # type: ignore[no-redef]
                except ImportError:
                    tomllib = None  # type: ignore[assignment]

            if tomllib:
                data = tomllib.loads(content)
                project_section = data.get("project", {})

                # PEP 621 dependencies
                dep_names = set()
                for dep_str in project_section.get("dependencies", []):
                    match = _PKG_RE.match(dep_str.strip())
                    if match:
                        name = match.group(1).lower().replace("_", "-")
                        dep_names.add(name)
                        direct_deps.append(
                            ParsedDependency(name=name, version=None, specifier=dep_str.strip())
                        )

                # Optional dependency groups
                optional_groups = project_section.get("optional-dependencies", {})
                for group_name, group_deps in optional_groups.items():
                    for dep_str in group_deps:
                        match = _PKG_RE.match(dep_str.strip())
                        if match:
                            name = match.group(1).lower().replace("_", "-")
                            optional_deps.append(
                                ParsedDependency(
                                    name=f"{name} [{group_name}]",
                                    version=None,
                                    specifier=dep_str.strip(),
                                )
                            )

                # Dev dependencies
                dev_dep_names = set()
                for dep_str in project_section.get("dev-dependencies", []):
                    match = _PKG_RE.match(dep_str.strip())
                    if match:
                        name = match.group(1).lower().replace("_", "-")
                        dev_dep_names.add(name)
                        dev_deps.append(
                            ParsedDependency(name=name, version=None, specifier=dep_str.strip())
                        )

                # Also check optional-dependencies.dev
                dev_optional = optional_groups.get("dev", [])
                for dep_str in dev_optional:
                    match = _PKG_RE.match(dep_str.strip())
                    if match:
                        name = match.group(1).lower().replace("_", "-")
                        if name not in dev_dep_names:
                            dev_dep_names.add(name)
                            dev_deps.append(
                                ParsedDependency(name=name, version=None, specifier=dep_str.strip())
                            )
        except Exception:
            pass

    # If we couldn't parse pyproject, fall back to all_deps as direct
    if not direct_deps:
        direct_deps = list(all_deps)

    # Transitive deps = all_deps - direct_deps (approximation without full resolve)
    # For a more accurate count, we'd need to resolve the dependency tree
    direct_names = {d.name for d in direct_deps}
    dev_names = {d.name for d in dev_deps}
    transitive_deps = [
        d for d in all_deps if d.name not in direct_names and d.name not in dev_names
    ]

    return direct_deps, dev_deps, optional_deps, transitive_deps


def _count_transitive_deps(
    direct_deps: list[ParsedDependency],
    direct_names: set[str],
    max_depth: int = 3,
) -> tuple[list[str], dict[str, list[str]]]:
    """Resolve transitive dependencies via PyPI.

    Returns:
        Tuple of (all_transitive_names, dependency_map).
    """
    transitive_names: set[str] = set()
    dep_map: dict[str, list[str]] = {}
    visited: set[str] = set(direct_names)

    with PyPIClient() as client:
        queue = list(direct_names)
        depth = 0
        while queue and depth < max_depth:
            next_queue: list[str] = []
            for pkg_name in queue:
                if pkg_name in visited:
                    continue
                visited.add(pkg_name)
                info = client.get_package_info(pkg_name)
                if info is None:
                    continue

                # Get requires_dist
                requires_dist = info.get("info", {}).get("requires_dist", []) or []
                sub_deps: list[str] = []
            for req_str in requires_dist:
                # Parse requirement — handle extras and version specs
                match = _PKG_RE.match(req_str.strip())
                if match:
                    sub_name = match.group(1).lower().replace("_", "-")
                    sub_name = re.sub(r"[-_.]+", "-", sub_name)  # noqa: RUF005
                    # Skip extras markers for simplicity
                    if ";" in req_str:
                        continue
                    sub_deps.append(sub_name)
                    if sub_name not in visited and sub_name not in direct_names:
                        transitive_names.add(sub_name)
                        next_queue.append(sub_name)

                dep_map[pkg_name] = sub_deps

            queue = next_queue
            depth += 1

    return sorted(transitive_names), dep_map


def check_budget(
    project_path: str | Path,
    config: BudgetConfig | None = None,
    resolve_transitive: bool = True,
) -> BudgetReport:
    """Check a project's dependency budget.

    Args:
        project_path: Path to the project directory.
        config: Budget configuration (loaded from pyproject.toml if None).
        resolve_transitive: Whether to resolve transitive deps via PyPI.

    Returns:
        A BudgetReport with budget analysis.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return BudgetReport(
            project_path=str(project_path),
            config=config or BudgetConfig(),
            errors=[f"Path is not a directory: {project_path}"],
        )

    # Load config from pyproject.toml if not provided
    if config is None:
        config = BudgetConfig.from_pyproject(project_path) or BudgetConfig()

    # Classify dependencies
    direct_deps, dev_deps, optional_deps, transitive_deps = _classify_dependencies(project_path)

    direct_names = [d.name for d in direct_deps]
    dev_names = [d.name for d in dev_deps]
    optional_names = [d.name for d in optional_deps]

    # Resolve transitive deps if requested
    transitive_names: list[str] = []
    if resolve_transitive and direct_deps:
        resolved_transitive, _ = _count_transitive_deps(direct_deps, set(direct_names), max_depth=3)
        transitive_names = resolved_transitive
    else:
        transitive_names = [d.name for d in transitive_deps]

    # Build report
    report = BudgetReport(
        project_path=str(project_path),
        config=config,
        total_deps=len(direct_names) + len(transitive_names),
        total_direct=len(direct_names),
        total_transitive=len(transitive_names),
        total_dev=len(dev_names),
        total_optional=len(optional_names),
    )

    # Build budget categories
    categories: list[BudgetCategory] = []

    # Total budget
    categories.append(
        BudgetCategory(
            name="total",
            limit=config.total,
            count=report.total_deps,
            packages=direct_names + transitive_names,
        )
    )

    # Direct budget
    categories.append(
        BudgetCategory(
            name="direct",
            limit=config.direct,
            count=report.total_direct,
            packages=direct_names,
        )
    )

    # Transitive budget
    categories.append(
        BudgetCategory(
            name="transitive",
            limit=config.transitive,
            count=report.total_transitive,
            packages=transitive_names,
        )
    )

    # Dev budget
    categories.append(
        BudgetCategory(
            name="dev",
            limit=config.dev,
            count=report.total_dev,
            packages=dev_names,
        )
    )

    # Optional budget
    categories.append(
        BudgetCategory(
            name="optional",
            limit=config.optional,
            count=report.total_optional,
            packages=optional_names,
        )
    )

    # Custom group budgets
    for group_name, group_limit in config.groups.items():
        # Try to match against optional dependency groups
        group_pkgs = _resolve_group_packages(project_path, group_name)
        categories.append(
            BudgetCategory(
                name=f"group:{group_name}",
                limit=group_limit,
                count=len(group_pkgs),
                packages=group_pkgs,
            )
        )

    report.categories = categories
    return report


def _resolve_group_packages(project_path: Path, group_name: str) -> list[str]:
    """Resolve package names for a custom budget group.

    Looks up optional-dependencies groups in pyproject.toml
    and extras in requirements.txt.
    """
    pyproject = project_path / "pyproject.toml"
    if pyproject.is_file():
        try:
            content = pyproject.read_text(encoding="utf-8")
            if sys.version_info >= (3, 11):
                import tomllib
            else:
                try:
                    import tomli as tomllib  # type: ignore[no-redef]
                except ImportError:
                    return []

            data = tomllib.loads(content)
            optional_deps = data.get("project", {}).get("optional-dependencies", {})
            group_deps = optional_deps.get(group_name, [])

            packages: list[str] = []
            for dep_str in group_deps:
                match = _PKG_RE.match(dep_str.strip())
                if match:
                    packages.append(match.group(1).lower().replace("_", "-"))
            return packages
        except Exception:
            pass

    return []


# ─── Rendering ─────────────────────────────────────────────────────────────


def render_budget_table(report: BudgetReport, console: Console | None = None) -> None:
    """Render budget report as a Rich table."""
    if console is None:
        console = Console()

    console.print(f"\n[bold]Dependency Budget: {report.project_path}[/bold]\n")

    table = Table(title="Budget Status", show_lines=True)
    table.add_column("Category", style="bold")
    table.add_column("Limit", justify="right")
    table.add_column("Count", justify="right")
    table.add_column("Remaining", justify="right")
    table.add_column("Utilization", justify="right")
    table.add_column("Status", justify="center")

    for cat in report.categories:
        limit_str = str(cat.limit) if cat.limit is not None else "∞"
        remaining_str = str(cat.remaining) if cat.remaining is not None else "∞"
        util_str = f"{cat.utilization}%" if cat.utilization is not None else "N/A"

        if cat.is_over:
            status = "[red]✗ OVER[/red]"
        elif cat.utilization is not None and cat.utilization >= 80:
            status = "[yellow]⚠ NEAR[/yellow]"
        else:
            status = "[green]✓ OK[/green]"

        table.add_row(
            cat.name,
            limit_str,
            str(cat.count),
            remaining_str,
            util_str,
            status,
        )

    console.print(table)

    # Show over-budget details
    over_cats = report.over_budget_categories
    if over_cats:
        console.print("\n[bold red]Over-budget categories:[/bold red]")
        for cat in over_cats:
            excess = cat.count - (cat.limit or 0)
            console.print(f"  [red]• {cat.name}: {cat.count}/{cat.limit} ({excess} over)[/red]")
            # Show first 10 packages
            for pkg in cat.packages[:10]:
                console.print(f"    - {pkg}")
            if len(cat.packages) > 10:
                console.print(f"    ... and {len(cat.packages) - 10} more")

    # Summary
    console.print("\n[bold]Summary:[/bold]")
    console.print(f"  Total dependencies: {report.total_deps}")
    console.print(f"  Direct: {report.total_direct}")
    console.print(f"  Transitive: {report.total_transitive}")
    console.print(f"  Dev: {report.total_dev}")
    console.print(f"  Optional: {report.total_optional}")

    if report.is_within_budget:
        console.print("\n[green]✓ All categories within budget[/green]")
    else:
        console.print(f"\n[red]✗ {len(over_cats)} category(s) over budget[/red]")


def render_budget_json(report: BudgetReport, console: Console | None = None) -> None:
    """Render budget report as JSON."""
    output = json.dumps(report.to_dict(), indent=2)
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(output)
