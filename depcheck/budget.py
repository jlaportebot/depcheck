"""Dependency budget management for depcheck.

Define and enforce dependency budgets for your project — limits on
total count, download size, install footprint, transitive depth, and
allowed categories. Catches budget violations early in CI and provides
clear reports of where budgets are being spent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.pypi import PyPIClient
from depcheck.scanner import discover_dependencies, normalize_package_name
from depcheck.size import _fetch_package_size, _human_size

# ── Data models ──────────────────────────────────────────────────────────


@dataclass
class BudgetRule:
    """A single budget constraint.

    Attributes:
        name: Human-readable rule name.
        metric: What to measure (count, download_kb, install_kb, max_deps, max_depth,
        license_category).
        limit: The budget limit value.
        current: Current measured value (filled after analysis).
        unit: Unit for display (e.g., "packages", "KB", "MB").
        severity: Violation severity (warning, error).
    """

    name: str = ""
    metric: str = ""
    limit: float = 0.0
    current: float = 0.0
    unit: str = ""
    severity: str = "error"

    @property
    def is_violated(self) -> bool:
        """Check if the budget rule is violated."""
        return self.current > self.limit

    @property
    def utilization(self) -> float:
        """Utilization as a percentage (0-100+)."""
        if self.limit <= 0:
            return 0.0
        return (self.current / self.limit) * 100.0

    @property
    def remaining(self) -> float:
        """Remaining budget."""
        return max(0.0, self.limit - self.current)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "metric": self.metric,
            "limit": self.limit,
            "current": self.current,
            "remaining": self.remaining,
            "unit": self.unit,
            "utilization_pct": round(self.utilization, 1),
            "is_violated": self.is_violated,
            "severity": self.severity,
        }


@dataclass
class BudgetConfig:
    """Budget configuration for a project.

    Attributes:
        max_packages: Maximum number of direct dependencies.
        max_total_download_kb: Maximum total download size in KB.
        max_total_install_kb: Maximum total install size in KB.
        max_single_package_kb: Maximum download size for a single package.
        max_transitive_depth: Maximum dependency tree depth.
        allowed_license_categories: Set of allowed license categories.
        denied_packages: Set of denied package names.
        required_packages: Set of required package names.
    """

    max_packages: int = 50
    max_total_download_kb: float = 500_000  # 500 MB
    max_total_install_kb: float = 1_000_000  # 1 GB
    max_single_package_kb: float = 100_000  # 100 MB
    max_transitive_depth: int = 6
    allowed_license_categories: set[str] = field(
        default_factory=lambda: {"permissive", "public_domain"},
    )
    denied_packages: set[str] = field(default_factory=set)
    required_packages: set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_packages": self.max_packages,
            "max_total_download_kb": self.max_total_download_kb,
            "max_total_install_kb": self.max_total_install_kb,
            "max_single_package_kb": self.max_single_package_kb,
            "max_transitive_depth": self.max_transitive_depth,
            "allowed_license_categories": sorted(self.allowed_license_categories),
            "denied_packages": sorted(self.denied_packages),
            "required_packages": sorted(self.required_packages),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> BudgetConfig:
        """Create a BudgetConfig from a dictionary.

        Args:
            data: Dictionary with budget configuration values.

        Returns:
            BudgetConfig instance.
        """
        config = cls()
        if "max_packages" in data:
            config.max_packages = int(data["max_packages"])
        if "max_total_download_kb" in data:
            config.max_total_download_kb = float(data["max_total_download_kb"])
        if "max_total_install_kb" in data:
            config.max_total_install_kb = float(data["max_total_install_kb"])
        if "max_single_package_kb" in data:
            config.max_single_package_kb = float(data["max_single_package_kb"])
        if "max_transitive_depth" in data:
            config.max_transitive_depth = int(data["max_transitive_depth"])
        if "allowed_license_categories" in data:
            config.allowed_license_categories = set(data["allowed_license_categories"])
        if "denied_packages" in data:
            config.denied_packages = {normalize_package_name(p) for p in data["denied_packages"]}
        if "required_packages" in data:
            config.required_packages = {
        normalize_package_name(p) for p in data["required_packages"]
    }
        return config

    @classmethod
    def from_file(cls, filepath: Path) -> BudgetConfig:
        """Load budget configuration from a JSON file.

        Args:
            filepath: Path to the budget config file.

        Returns:
            BudgetConfig instance.
        """
        try:
            content = filepath.read_text(encoding="utf-8")
            data = json.loads(content)
            return cls.from_dict(data)
        except Exception:
            return cls()  # Return defaults on error


@dataclass
class BudgetReport:
    """Result of budget compliance analysis.

    Attributes:
        project_path: Path to the analyzed project.
        config: The budget configuration used.
        rules: List of evaluated budget rules.
        violations: List of violated rules.
        warnings: List of rules that are close to being violated (>80%).
        package_details: Size and license info for each package.
        total_packages: Total number of direct dependencies.
        total_download_kb: Total download size.
        total_install_kb: Total estimated install size.
        is_compliant: Whether all rules are satisfied.
    """

    project_path: str = ""
    config: BudgetConfig = field(default_factory=BudgetConfig)
    rules: list[BudgetRule] = field(default_factory=list)
    violations: list[BudgetRule] = field(default_factory=list)
    warnings: list[BudgetRule] = field(default_factory=list)
    package_details: list[dict[str, Any]] = field(default_factory=list)
    total_packages: int = 0
    total_download_kb: float = 0.0
    total_install_kb: float = 0.0

    @property
    def is_compliant(self) -> bool:
        """Check if the project is budget-compliant (no error violations)."""
        return not any(r.severity == "error" and r.is_violated for r in self.rules)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "is_compliant": self.is_compliant,
            "total_packages": self.total_packages,
            "total_download_kb": round(self.total_download_kb, 1),
            "total_install_kb": round(self.total_install_kb, 1),
            "config": self.config.to_dict(),
            "rules": [r.to_dict() for r in self.rules],
            "violations": [r.to_dict() for r in self.violations],
            "warnings": [r.to_dict() for r in self.warnings],
            "package_details": self.package_details,
        }


# ── Budget analysis implementation ──────────────────────────────────────


def _classify_license_simple(license_str: str) -> str:
    """Quick license classification from raw string.

    Args:
        license_str: Raw license string.

    Returns:
        Category string (permissive, copyleft, proprietary, unknown).
    """
    if not license_str:
        return "unknown"
    lower = license_str.lower()
    if any(kw in lower for kw in ("mit", "bsd", "apache", "isc")):
        return "permissive"
    if any(kw in lower for kw in ("gpl", "agpl", "lgpl", "mpl")):
        return "copyleft"
    if any(kw in lower for kw in ("cc0", "unlicense", "public domain")):
        return "public_domain"
    if any(kw in lower for kw in ("proprietary", "commercial")):
        return "proprietary"
    return "unknown"


def check_budget(
    project_path: str | Path,
    config: BudgetConfig | None = None,
) -> BudgetReport:
    """Check a project's dependencies against budget constraints.

    Args:
        project_path: Path to the project directory.
        config: Budget configuration (uses defaults if None).

    Returns:
        BudgetReport with compliance details.
    """
    project_path = Path(project_path).resolve()
    if config is None:
        config = BudgetConfig()

    report = BudgetReport(
        project_path=str(project_path),
        config=config,
    )

    # Try loading config from project if not explicitly provided
    budget_file = project_path / "depcheck.budget.json"
    if budget_file.is_file() and config == BudgetConfig():
        config = BudgetConfig.from_file(budget_file)
        report.config = config

    if not project_path.is_dir():
        report.violations.append(
            BudgetRule(name="project_path", metric="path", severity="error")
        )
        return report

    # Discover dependencies
    dependencies, _ = discover_dependencies(project_path)
    if not dependencies:
        report.violations.append(
            BudgetRule(
                name="no_dependencies",
                metric="count",
                limit=1,
                current=0,
                unit="packages",
                severity="warning",
            )
        )
        return report

    report.total_packages = len(dependencies)

    # Fetch package details
    total_download = 0.0
    total_install = 0.0
    package_details: list[dict[str, Any]] = []

    with PyPIClient() as pypi_client:
        for dep in dependencies:
            try:
                size_info = _fetch_package_size(pypi_client, dep.name, dep.version)

                # Get license info
                info = pypi_client.get_package_info(dep.name)
                raw_license = ""
                if info:
                    pkg_info = info.get("info", {})
                    raw_license = pkg_info.get("license", "") or ""
                    # Try classifiers
                    classifiers = pkg_info.get("classifiers", []) or []
                    for cls in classifiers:
                        if cls.startswith("License ::"):
                            parts = cls.split("::")
                            if len(parts) >= 3:
                                classifier_lic = parts[-1].strip()
                                if classifier_lic not in ("OSI Approved", "Other/Proprietary"):
                                    raw_license = classifier_lic
                                    break

                license_cat = _classify_license_simple(raw_license)

                detail = {
                    "name": dep.name,
                    "version": dep.version or size_info.version,
                    "download_kb": round(size_info.download_size_kb, 1),
                    "install_kb": round(size_info.estimated_install_kb, 1),
                    "category": size_info.category,
                    "license": raw_license,
                    "license_category": license_cat,
                }
                package_details.append(detail)

                total_download += size_info.download_size_kb
                total_install += size_info.estimated_install_kb

            except Exception:
                package_details.append({
                    "name": dep.name,
                    "version": dep.version or "unknown",
                    "download_kb": 0,
                    "install_kb": 0,
                    "category": "unknown",
                    "license": "",
                    "license_category": "unknown",
                })

    report.package_details = package_details
    report.total_download_kb = total_download
    report.total_install_kb = total_install

    # ── Evaluate budget rules ────────────────────────────────────────────

    # Rule 1: Package count
    rule = BudgetRule(
        name="Package Count",
        metric="count",
        limit=config.max_packages,
        current=len(dependencies),
        unit="packages",
        severity="error",
    )
    report.rules.append(rule)

    # Rule 2: Total download size
    rule = BudgetRule(
        name="Total Download Size",
        metric="download_kb",
        limit=config.max_total_download_kb,
        current=total_download,
        unit="KB",
        severity="error",
    )
    report.rules.append(rule)

    # Rule 3: Total install size
    rule = BudgetRule(
        name="Total Install Size",
        metric="install_kb",
        limit=config.max_total_install_kb,
        current=total_install,
        unit="KB",
        severity="error",
    )
    report.rules.append(rule)

    # Rule 4: Single package size
    max_pkg = max(package_details, key=lambda p: p.get("download_kb", 0)) if package_details else {}
    rule = BudgetRule(
        name=f"Largest Package ({max_pkg.get('name', 'N/A')})",
        metric="single_package_kb",
        limit=config.max_single_package_kb,
        current=max_pkg.get("download_kb", 0),
        unit="KB",
        severity="warning",
    )
    report.rules.append(rule)

    # Rule 5: License category compliance
    non_compliant_licenses = [
        p for p in package_details
        if p.get("license_category", "unknown") not in config.allowed_license_categories
        and p.get("license_category", "unknown") != "unknown"
    ]
    rule = BudgetRule(
        name="License Compliance",
        metric="license_category",
        limit=0,  # Zero non-compliant packages allowed
        current=len(non_compliant_licenses),
        unit="packages",
        severity="warning",
    )
    report.rules.append(rule)

    # Rule 6: Denied packages
    found_denied = [
        p for p in package_details
        if normalize_package_name(p.get("name", "")) in config.denied_packages
    ]
    rule = BudgetRule(
        name="Denied Packages",
        metric="denied_packages",
        limit=0,
        current=len(found_denied),
        unit="packages",
        severity="error",
    )
    report.rules.append(rule)

    # Rule 7: Required packages
    present_names = {normalize_package_name(p.get("name", "")) for p in package_details}
    missing_required = config.required_packages - present_names
    rule = BudgetRule(
        name="Required Packages",
        metric="required_packages",
        limit=len(config.required_packages),
        current=len(config.required_packages) - len(missing_required),
        unit="packages",
        severity="warning" if missing_required else "error",
    )
    report.rules.append(rule)

    # ── Classify violations and warnings ──────────────────────────────────

    for rule in report.rules:
        if rule.is_violated:
            report.violations.append(rule)
        elif rule.utilization >= 80:
            report.warnings.append(rule)

    return report


def init_budget_file(project_path: str | Path) -> Path:
    """Create a default budget configuration file.

    Args:
        project_path: Path to the project directory.

    Returns:
        Path to the created budget file.
    """
    project_path = Path(project_path).resolve()
    config = BudgetConfig()
    filepath = project_path / "depcheck.budget.json"

    filepath.write_text(
        json.dumps(config.to_dict(), indent=2) + "\n",
        encoding="utf-8",
    )

    return filepath


# ── Rendering ────────────────────────────────────────────────────────────


def render_budget_table(report: BudgetReport, console: Console | None = None) -> None:
    """Render a budget compliance report as Rich tables.

    Args:
        report: The budget report to render.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    console.print()

    status_icon = "✅" if report.is_compliant else "❌"
    status_color = "green" if report.is_compliant else "red"
    console.print(
        Panel(
            f"[bold]depcheck budget[/bold] — Dependency Budget Report\n"
            f"[dim]Project: {report.project_path}[/dim]\n"
            f"[{status_color}]{status_icon} "
f"{'COMPLIANT' if report.is_compliant else 'VIOLATIONS FOUND'}[/{status_color}]",
    f"[/{status_color}]",
            border_style=status_color,
        )
    )

    if not report.rules:
        console.print("[dim]No budget rules evaluated.[/dim]")
        return

    # Budget rules table
    table = Table(
        title="Budget Rules",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        pad_edge=False,
        expand=True,
    )

    table.add_column("Rule", style="bold", min_width=25)
    table.add_column("Current", min_width=12, justify="right")
    table.add_column("Limit", min_width=12, justify="right")
    table.add_column("Remaining", min_width=12, justify="right")
    table.add_column("Utilization", min_width=12, justify="center")
    table.add_column("Status", width=10, justify="center")

    for rule in report.rules:
        # Format current/limit values
        if rule.metric in ("download_kb", "install_kb", "single_package_kb"):
            current_str = _human_size(rule.current)
            limit_str = _human_size(rule.limit)
            remaining_str = _human_size(rule.remaining)
        else:
            current_str = f"{int(rule.current)} {rule.unit}"
            limit_str = f"{int(rule.limit)} {rule.unit}"
            remaining_str = f"{int(rule.remaining)} {rule.unit}"

        # Utilization bar
        util = rule.utilization
        if util > 100:
            util_str = f"[red]{util:.0f}%[/red]"
        elif util >= 80:
            util_str = f"[yellow]{util:.0f}%[/yellow]"
        else:
            util_str = f"[green]{util:.0f}%[/green]"

        # Status icon
        if rule.is_violated:
            status = "[red]✗ FAIL[/red]"
        elif rule.utilization >= 80:
            status = "[yellow]⚠ WARN[/yellow]"
        else:
            status = "[green]✓ OK[/green]"

        table.add_row(
            rule.name,
            current_str,
            limit_str,
            remaining_str,
            util_str,
            status,
        )

    console.print(table)

    # Violations detail
    if report.violations:
        console.print()
        console.print("[bold red]Violations:[/bold red]")
        for v in report.violations:
            if v.metric in ("download_kb", "install_kb", "single_package_kb"):
                over_by = _human_size(v.current - v.limit)
                console.print(
                    f"  [red]✗[/red] {v.name}: over budget by {over_by} "
                    f"({v.utilization:.0f}% utilization)"
                )
            else:
                over_by = int(v.current - v.limit)
                console.print(
                    f"  [red]✗[/red] {v.name}: {over_by} {v.unit} over limit"
                )

    # Warnings detail
    if report.warnings:
        console.print()
        console.print("[bold yellow]Warnings:[/bold yellow]")
        for w in report.warnings:
            size_str = (
                _human_size(w.remaining)
                if 'kb' in w.metric
                else f'{int(w.remaining)} {w.unit}'
            )
            console.print(
                f"  [yellow]⚠[/yellow] {w.name}: {w.utilization:.0f}%"
                f" utilization ({size_str} remaining)"
            )

    # Package details table
    if report.package_details:
        console.print()
        pkg_table = Table(
            title="Package Budget Details",
            show_header=True,
            header_style="bold cyan",
            show_lines=False,
            pad_edge=False,
        )

        pkg_table.add_column("Package", style="bold", min_width=20)
        pkg_table.add_column("Version", min_width=10)
        pkg_table.add_column("Download", min_width=10, justify="right")
        pkg_table.add_column("Install", min_width=10, justify="right")
        pkg_table.add_column("Category", min_width=8)
        pkg_table.add_column("License", min_width=12)

        for pkg in sorted(
    report.package_details, key=lambda p: p.get("download_kb", 0), reverse=True
):
            dl_kb = pkg.get("download_kb", 0)
            inst_kb = pkg.get("install_kb", 0)
            cat = pkg.get("category", "unknown")
            lic = pkg.get("license", "Unknown") or "Unknown"
            lic_cat = pkg.get("license_category", "unknown")

            cat_colors = {
                "tiny": "green", "small": "green", "medium": "yellow",
                "large": "red", "very_large": "red bold", "unknown": "dim",
            }
            lic_colors = {
                "permissive": "green", "copyleft": "yellow",
                "public_domain": "green", "proprietary": "red", "unknown": "dim",
            }
            cat_color = cat_colors.get(cat, "white")
            lic_color = lic_colors.get(lic_cat, "white")

            pkg_table.add_row(
                f"[cyan]{pkg.get('name', '')}[/cyan]",
                pkg.get("version", "—"),
                _human_size(dl_kb),
                _human_size(inst_kb),
                f"[{cat_color}]{cat}[/{cat_color}]",
                f"[{lic_color}]{lic[:20]}[/{lic_color}]",
            )

        console.print(pkg_table)

    console.print()


def render_budget_json(report: BudgetReport) -> str:
    """Render budget report as JSON string.

    Args:
        report: The budget report to render.

    Returns:
        JSON string.
    """
    return json.dumps(report.to_dict(), indent=2)
