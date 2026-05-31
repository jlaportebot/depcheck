"""Safe update strategy planner for Python dependencies.

Generates a prioritized, risk-aware update plan that considers:
- Semver compatibility (patch/minor/major)
- Vulnerability status (security updates first)
- Breaking change indicators from changelogs
- Dependency constraint conflicts
- Test coverage signals

Produces a step-by-step update plan with commands and risk annotations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import HealthStatus, ScanResult
from depcheck.outdated import (
    RiskLevel,
    UpgradeLevel,
    assess_risk,
    classify_upgrade_level,
    compute_days_behind,
    guess_changelog_url,
)


class UpdatePriority:
    """Priority levels for update scheduling."""

    CRITICAL = "critical"  # Vulnerable packages
    HIGH = "high"  # Major upgrades or very outdated
    MEDIUM = "medium"  # Minor upgrades
    LOW = "low"  # Patch upgrades
    DEFERRED = "deferred"  # Prerelease or unknown


class UpdateStrategy:
    """Strategy for how to apply an update."""

    DIRECT = "direct"  # pip install --upgrade pkg
    STAGED = "staged"  # Update to latest minor first, then major
    SKIP = "skip"  # Don't update (pinned, unsafe, etc.)
    REVIEW = "review"  # Needs manual review before updating


@dataclass
class UpdateStep:
    """A single step in the update plan."""

    name: str
    current_version: str
    target_version: str
    priority: str = UpdatePriority.LOW
    strategy: str = UpdateStrategy.DIRECT
    risk: str = RiskLevel.UNKNOWN
    upgrade_level: str = UpgradeLevel.UNKNOWN
    command: str = ""
    pre_update_command: str | None = None
    post_update_command: str | None = None
    rationale: str = ""
    changelog_url: str | None = None
    days_behind: int | None = None
    is_vulnerable: bool = False
    breaking_change_risk: str = "low"
    intermediate_version: str | None = None
    dep_constraints: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "current_version": self.current_version,
            "target_version": self.target_version,
            "priority": self.priority,
            "strategy": self.strategy,
            "risk": self.risk,
            "upgrade_level": self.upgrade_level,
            "command": self.command,
            "pre_update_command": self.pre_update_command,
            "post_update_command": self.post_update_command,
            "rationale": self.rationale,
            "changelog_url": self.changelog_url,
            "days_behind": self.days_behind,
            "is_vulnerable": self.is_vulnerable,
            "breaking_change_risk": self.breaking_change_risk,
            "intermediate_version": self.intermediate_version,
            "dep_constraints": self.dep_constraints,
        }


@dataclass
class UpdatePlan:
    """A complete update plan for a project's dependencies."""

    steps: list[UpdateStep] = field(default_factory=list)
    total_packages: int = 0
    up_to_date_count: int = 0
    needs_update_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    deferred_count: int = 0
    estimated_time_minutes: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "total_packages": self.total_packages,
                "up_to_date": self.up_to_date_count,
                "needs_update": self.needs_update_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "deferred": self.deferred_count,
                "estimated_time_minutes": self.estimated_time_minutes,
            },
            "steps": [s.to_dict() for s in self.steps],
            "errors": self.errors,
        }


def determine_update_priority(
    pkg_report: Any,
    upgrade_level: str,
    risk: str,
    is_vulnerable: bool,
    days_behind: int | None,
) -> str:
    """Determine the update priority for a package.

    Security vulnerabilities always get CRITICAL priority.
    Major upgrades with long drift get HIGH.
    Minor upgrades get MEDIUM.
    Patch upgrades get LOW.
    Prereleases get DEFERRED.

    Args:
        pkg_report: The PackageReport from scanning.
        upgrade_level: The semver classification.
        risk: The risk assessment.
        is_vulnerable: Whether the package has known vulnerabilities.
        days_behind: Number of days behind the latest version.

    Returns:
        One of UpdatePriority constants.
    """
    if is_vulnerable:
        return UpdatePriority.CRITICAL

    if upgrade_level == UpgradeLevel.MAJOR:
        if days_behind is not None and days_behind > 365:
            return UpdatePriority.HIGH
        return UpdatePriority.HIGH

    if upgrade_level == UpgradeLevel.MINOR:
        if days_behind is not None and days_behind > 180:
            return UpdatePriority.HIGH
        return UpdatePriority.MEDIUM

    if upgrade_level == UpgradeLevel.PATCH:
        return UpdatePriority.LOW

    if upgrade_level == UpgradeLevel.PRERELEASE:
        return UpdatePriority.DEFERRED

    return UpdatePriority.DEFERRED


def determine_update_strategy(
    upgrade_level: str,
    is_vulnerable: bool,
    has_dep_constraints: bool,
    is_pinned: bool,
) -> str:
    """Determine the best update strategy for a package.

    Args:
        upgrade_level: The semver classification.
        is_vulnerable: Whether the package has vulnerabilities.
        has_dep_constraints: Whether other packages constrain this one.
        is_pinned: Whether the package is pinned to an exact version.

    Returns:
        One of UpdateStrategy constants.
    """
    if is_pinned and not is_vulnerable:
        return UpdateStrategy.REVIEW

    if is_vulnerable:
        return UpdateStrategy.DIRECT

    if upgrade_level == UpgradeLevel.MAJOR:
        if has_dep_constraints:
            return UpdateStrategy.STAGED
        return UpdateStrategy.REVIEW

    if upgrade_level == UpgradeLevel.MINOR and has_dep_constraints:
        return UpdateStrategy.STAGED

    if upgrade_level == UpgradeLevel.PRERELEASE:
        return UpdateStrategy.SKIP

    return UpdateStrategy.DIRECT


def assess_breaking_change_risk(
    upgrade_level: str,
    is_vulnerable: bool,
    days_behind: int | None,
) -> str:
    """Assess the likelihood of breaking changes from an update.

    Args:
        upgrade_level: The semver classification.
        is_vulnerable: Whether the package has vulnerabilities.
        days_behind: How many days behind the latest release.

    Returns:
        "low", "medium", or "high".
    """
    if upgrade_level == UpgradeLevel.MAJOR:
        if days_behind is not None and days_behind > 365:
            return "high"
        return "medium"

    if upgrade_level == UpgradeLevel.MINOR:
        if days_behind is not None and days_behind > 180:
            return "medium"
        return "low"

    if upgrade_level == UpgradeLevel.PATCH:
        return "low"

    if is_vulnerable:
        return "high"

    return "low"


def estimate_update_time(steps: list[UpdateStep]) -> int:
    """Estimate total update time in minutes based on plan complexity.

    Args:
        steps: List of update steps.

    Returns:
        Estimated minutes.
    """
    total = 0
    for step in steps:
        if step.priority == UpdatePriority.CRITICAL:
            total += 5  # Urgent, should be done immediately
        elif step.priority == UpdatePriority.HIGH:
            total += 10  # Needs careful review
        elif step.priority == UpdatePriority.MEDIUM:
            total += 5
        elif step.priority == UpdatePriority.LOW:
            total += 2
        # STAGED updates take more time
        if step.strategy == UpdateStrategy.STAGED:
            total += 5
        # REVIEW updates need manual intervention time
        if step.strategy == UpdateStrategy.REVIEW:
            total += 15
    return total


def build_update_plan(
    scan_result: ScanResult,
    pypi_infos: dict[str, dict[str, Any]] | None = None,
    pinned_packages: set[str] | None = None,
) -> UpdatePlan:
    """Build a comprehensive update plan from a scan result.

    Prioritizes security fixes, then orders by semver impact.
    Generates pip commands for each step.

    Args:
        scan_result: The raw scan result from scan_project().
        pypi_infos: Optional pre-fetched PyPI info for changelogs.
        pinned_packages: Set of package names that are pinned (exact version).

    Returns:
        An UpdatePlan with prioritized steps and commands.
    """
    plan = UpdatePlan(
        total_packages=len(scan_result.packages),
        errors=list(scan_result.errors),
    )

    pinned = pinned_packages or set()

    for pkg in scan_result.packages:
        if pkg.status == HealthStatus.HEALTHY:
            plan.up_to_date_count += 1
            continue

        if not pkg.latest_version or not pkg.installed_version:
            continue

        if pkg.installed_version == "unknown":
            continue

        is_vulnerable = pkg.is_vulnerable
        upgrade_level = classify_upgrade_level(pkg.installed_version, pkg.latest_version)
        days = compute_days_behind(pkg.last_release_date, None)
        risk = assess_risk(upgrade_level, days)
        is_pinned = pkg.name in pinned

        # Determine constraints — for now, just flag if version specifier is exact
        dep_constraints: list[str] = []
        if pkg.latest_version:
            dep_constraints.append(f"current: {pkg.installed_version}")

        priority = determine_update_priority(pkg, upgrade_level, risk, is_vulnerable, days)
        strategy = determine_update_strategy(
            upgrade_level, is_vulnerable, bool(dep_constraints), is_pinned
        )
        breaking_risk = assess_breaking_change_risk(upgrade_level, is_vulnerable, days)

        changelog = None
        if pypi_infos and pkg.name in pypi_infos:
            changelog = guess_changelog_url(pkg.name, pypi_infos[pkg.name])
        else:
            changelog = guess_changelog_url(pkg.name)

        # Build the pip command
        command = f"pip install --upgrade {pkg.name}=={pkg.latest_version}"

        # Build rationale
        rationale_parts: list[str] = []
        if is_vulnerable:
            rationale_parts.append("has known vulnerabilities")
        if upgrade_level == UpgradeLevel.MAJOR:
            rationale_parts.append("major version upgrade")
        elif upgrade_level == UpgradeLevel.MINOR:
            rationale_parts.append("minor version upgrade")
        elif upgrade_level == UpgradeLevel.PATCH:
            rationale_parts.append("patch version upgrade")
        if days is not None and days > 365:
            rationale_parts.append(f"{days}d behind latest")
        rationale = "; ".join(rationale_parts) if rationale_parts else "update available"

        # Pre/post update commands
        pre_cmd = None
        post_cmd = None
        if strategy == UpdateStrategy.STAGED:
            # For staged updates, first update to latest minor in same major
            pre_cmd = f"# Consider updating to latest {pkg.installed_version.split('.')[0]}.x first"
        if strategy == UpdateStrategy.REVIEW:
            pre_cmd = f"# Review {changelog or 'changelog'} before updating"
        if is_vulnerable:
            post_cmd = "# Verify fix: depcheck scan ."

        step = UpdateStep(
            name=pkg.name,
            current_version=pkg.installed_version,
            target_version=pkg.latest_version,
            priority=priority,
            strategy=strategy,
            risk=risk,
            upgrade_level=upgrade_level,
            command=command,
            pre_update_command=pre_cmd,
            post_update_command=post_cmd,
            rationale=rationale,
            changelog_url=changelog,
            days_behind=days,
            is_vulnerable=is_vulnerable,
            breaking_change_risk=breaking_risk,
            dep_constraints=dep_constraints,
        )
        plan.steps.append(step)
        plan.needs_update_count += 1

        if priority == UpdatePriority.CRITICAL:
            plan.critical_count += 1
        elif priority == UpdatePriority.HIGH:
            plan.high_count += 1
        elif priority == UpdatePriority.MEDIUM:
            plan.medium_count += 1
        elif priority == UpdatePriority.LOW:
            plan.low_count += 1
        else:
            plan.deferred_count += 1

    # Sort steps by priority
    priority_order = {
        UpdatePriority.CRITICAL: 0,
        UpdatePriority.HIGH: 1,
        UpdatePriority.MEDIUM: 2,
        UpdatePriority.LOW: 3,
        UpdatePriority.DEFERRED: 4,
    }
    plan.steps.sort(key=lambda s: (priority_order.get(s.priority, 4), s.name))

    plan.estimated_time_minutes = estimate_update_time(plan.steps)

    return plan


def render_update_plan_table(plan: UpdatePlan, console: Console | None = None) -> None:
    """Render the update plan as a Rich table with priority ordering.

    Args:
        plan: The UpdatePlan to render.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    if not plan.steps:
        console.print("[green]✓ All dependencies are up to date — no updates needed![/green]")
        return

    # Summary panel
    parts: list[str] = []
    if plan.critical_count:
        parts.append(f"[red bold]{plan.critical_count} critical (security)[/red bold]")
    if plan.high_count:
        parts.append(f"[red]{plan.high_count} high[/red]")
    if plan.medium_count:
        parts.append(f"[yellow]{plan.medium_count} medium[/yellow]")
    if plan.low_count:
        parts.append(f"[green]{plan.low_count} low[/green]")
    if plan.deferred_count:
        parts.append(f"[dim]{plan.deferred_count} deferred[/dim]")

    summary = "Updates: " + ", ".join(parts)
    summary += f" • {plan.up_to_date_count} up to date • {plan.total_packages} total"
    summary += f" • ~{plan.estimated_time_minutes}min estimated"

    console.print()
    console.print(Panel(summary, title="Update Plan", border_style="blue"))

    # Main table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Priority", justify="center", min_width=10)
    table.add_column("Package", style="cyan", min_width=20)
    table.add_column("Current", justify="right", min_width=12)
    table.add_column("Target", justify="right", min_width=12)
    table.add_column("Strategy", justify="center", min_width=10)
    table.add_column("Risk", justify="center", min_width=8)
    table.add_column("Rationale", min_width=30)

    priority_styles = {
        UpdatePriority.CRITICAL: "red bold",
        UpdatePriority.HIGH: "red",
        UpdatePriority.MEDIUM: "yellow",
        UpdatePriority.LOW: "green",
        UpdatePriority.DEFERRED: "dim",
    }

    priority_icons = {
        UpdatePriority.CRITICAL: "🔴 CRIT",
        UpdatePriority.HIGH: "⬆ HIGH",
        UpdatePriority.MEDIUM: "↗ MED",
        UpdatePriority.LOW: "· LOW",
        UpdatePriority.DEFERRED: "⏸ SKIP",
    }

    strategy_icons = {
        UpdateStrategy.DIRECT: "→ direct",
        UpdateStrategy.STAGED: "⇢ staged",
        UpdateStrategy.REVIEW: "🔍 review",
        UpdateStrategy.SKIP: "⏭ skip",
    }

    risk_colors = {
        RiskLevel.LOW: "green",
        RiskLevel.MEDIUM: "yellow",
        RiskLevel.HIGH: "red",
        RiskLevel.UNKNOWN: "dim",
    }

    for step in plan.steps:
        style = priority_styles.get(step.priority, "dim")
        icon = priority_icons.get(step.priority, "?")
        strat = strategy_icons.get(step.strategy, "?")
        risk_color = risk_colors.get(step.risk, "dim")

        table.add_row(
            f"[{style}]{icon}[/{style}]",
            step.name,
            step.current_version,
            f"[bold]{step.target_version}[/bold]",
            strat,
            f"[{risk_color}]{step.risk.upper()}[/{risk_color}]",
            step.rationale,
        )

    console.print(table)

    # Show commands section
    console.print()
    console.print("[bold]Update commands (in priority order):[/bold]")
    console.print()
    for step in plan.steps:
        if step.strategy == UpdateStrategy.SKIP:
            continue
        if step.pre_update_command:
            console.print(f"  {step.pre_update_command}")
        style = priority_styles.get(step.priority, "dim")
        console.print(f"  [{style}]$ {step.command}[/{style}]")
        if step.post_update_command:
            console.print(f"  {step.post_update_command}")


def render_update_plan_json(plan: UpdatePlan) -> str:
    """Render the update plan as JSON string.

    Args:
        plan: The UpdatePlan to render.

    Returns:
        JSON string of the plan.
    """
    import json

    return json.dumps(plan.to_dict(), indent=2)
