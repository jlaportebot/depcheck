"""Dependency alternatives and recommendations for depcheck.

Analyzes project dependencies and suggests healthier alternatives based on:
- Maintenance health (active development, recent releases)
- Security posture (known vulnerabilities, CVE history)
- Popularity (download counts, GitHub stars as proxies)
- License compatibility
- Community adoption trends

Provides actionable migration advice with compatibility analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from depcheck.models import HealthStatus, PackageReport, ScanResult
from depcheck.scanner import normalize_package_name

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AlternativeReason(Enum):
    """Reason for suggesting an alternative."""

    VULNERABLE = "vulnerable"
    UNMAINTAINED = "unmaintained"
    YANKED = "yanked"
    REMOVED = "removed"
    OUTDATED_MAJOR = "outdated_major"
    BETTER_ALTERNATIVE = "better_alternative"
    LICENSE_ISSUE = "license_issue"
    LOWER_POPULARITY = "lower_popularity"


class MigrationDifficulty(Enum):
    """Difficulty level for migrating to an alternative."""

    TRIVIAL = "trivial"
    EASY = "easy"
    MODERATE = "moderate"
    HARD = "hard"
    UNKNOWN = "unknown"


class SuggestionConfidence(Enum):
    """Confidence level for a suggestion."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SPECULATIVE = "speculative"


# ---------------------------------------------------------------------------
# Known alternatives database
# ---------------------------------------------------------------------------

_KNOWN_ALTERNATIVES: dict[str, list[dict[str, Any]]] = {
    "requests": [
        {
            "name": "httpx",
            "reason": "better_alternative",
            "difficulty": "easy",
            "confidence": "high",
            "advantages": [
                "Async support built-in",
                "HTTP/2 support",
                "Modern API design",
            ],
            "migration_notes": (
                "Replace `requests.get()` with `httpx.get()`. "
                "For async, use `httpx.AsyncClient`. Session becomes `httpx.Client`. "
                "Most API is compatible; check timeout and retry behavior."
            ),
        },
        {
            "name": "aiohttp",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "Native async/await",
                "High performance",
                "WebSocket support",
            ],
            "migration_notes": (
                "Requires async code. Use `aiohttp.ClientSession()` "
                "instead of `requests.Session()`. Response access differs: "
                "`await resp.text()` instead of `resp.text`."
            ),
        },
    ],
    "urllib3": [
        {
            "name": "httpx",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "medium",
            "advantages": [
                "Higher-level API",
                "Connection pooling with async",
            ],
            "migration_notes": (
                "httpx uses urllib3 under the hood for sync. "
                "If you're using urllib3 directly, consider httpx for a higher-level API."
            ),
        },
    ],
    "flask": [
        {
            "name": "fastapi",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "Automatic OpenAPI docs",
                "Type validation with Pydantic",
                "Async support",
                "Higher performance",
            ],
            "migration_notes": (
                "Replace route decorators: `@app.route` -> `@app.get/post`. "
                "Add type hints for automatic validation. Use `Depends()` for DI. "
                "Templates need Jinja2Templates separately."
            ),
        },
    ],
    "django": [
        {
            "name": "fastapi",
            "reason": "better_alternative",
            "difficulty": "hard",
            "confidence": "medium",
            "advantages": [
                "Async-native",
                "Type safety",
                "Auto documentation",
            ],
            "migration_notes": (
                "Not a drop-in replacement. Django provides ORM, admin, "
                "auth, etc. If you need a lighter API-only framework, FastAPI is excellent. "
                "Consider keeping Django for full-stack apps."
            ),
        },
        {
            "name": "litestar",
            "reason": "better_alternative",
            "difficulty": "hard",
            "confidence": "medium",
            "advantages": [
                "ASGI-native",
                "Automatic OpenAPI",
                "Dependency injection",
            ],
            "migration_notes": (
                "Similar scope to FastAPI but with more opinionated "
                "structure. Better for larger projects needing conventions."
            ),
        },
    ],
    "pyyaml": [
        {
            "name": "ruamel.yaml",
            "reason": "better_alternative",
            "difficulty": "easy",
            "confidence": "high",
            "advantages": [
                "Preserves comments and formatting",
                "Better YAML 1.2 compliance",
                "Round-trip editing",
            ],
            "migration_notes": (
                "Replace `yaml.load()` with `ruamel.yaml.YAML().load()`. "
                "Output preserves formatting. API is slightly different but well-documented."
            ),
        },
    ],
    "argparse": [
        {
            "name": "click",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "Decorator-based API",
                "Automatic help formatting",
                "Type conversion",
                "Subcommand support",
            ],
            "migration_notes": (
                "Rewrite using `@click.command()` and `@click.option()`. "
                "Not API-compatible but migration is straightforward."
            ),
        },
        {
            "name": "typer",
            "reason": "better_alternative",
            "difficulty": "easy",
            "confidence": "high",
            "advantages": [
                "Type-hint driven",
                "Automatic help from docstrings",
                "Built on Click",
            ],
            "migration_notes": (
                "Define functions with type hints, add `typer.run()`. "
                "Very fast migration from simple argparse scripts."
            ),
        },
    ],
    "configparser": [
        {
            "name": "tomli",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "TOML is the Python standard (PEP 621)",
                "Better type support",
                "Widely adopted",
            ],
            "migration_notes": (
                "Convert .ini/.cfg files to .toml. TOML supports "
                "arrays, inline tables, and proper types. PEP 621 uses TOML for metadata."
            ),
        },
    ],
    "logging": [
        {
            "name": "loguru",
            "reason": "better_alternative",
            "difficulty": "easy",
            "confidence": "high",
            "advantages": [
                "Zero configuration",
                "Structured logging",
                "Better formatting",
                "Exception traceback formatting",
            ],
            "migration_notes": (
                "Replace `import logging; logger = logging.getLogger(__name__)` "
                "with `from loguru import logger`. Most methods are the same. "
                "Remove `basicConfig()` calls."
            ),
        },
        {
            "name": "structlog",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "Structured key-value logging",
                "JSON output for log aggregation",
                "Async-compatible",
            ],
            "migration_notes": (
                "Requires more setup than loguru but more flexible. "
                "Good for applications needing structured log output for ELK/Splunk."
            ),
        },
    ],
    "json": [
        {
            "name": "orjson",
            "reason": "better_alternative",
            "difficulty": "easy",
            "confidence": "high",
            "advantages": [
                "3-10x faster",
                "Proper datetime/UUID handling",
                "Compact output",
            ],
            "migration_notes": (
                "Replace `json.dumps()` with `orjson.dumps()` (returns bytes). "
                "Use `orjson.loads()` for parsing. Note: orjson.dumps() returns bytes, not str."
            ),
        },
    ],
    "selenium": [
        {
            "name": "playwright",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "Built-in auto-wait",
                "Multi-browser support",
                "Better performance",
                "Network interception",
            ],
            "migration_notes": (
                "Replace webdriver setup with `playwright.chromium.launch()`. "
                "Use `page.goto()`, `page.locator()`, `page.fill()`. "
                "Auto-wait eliminates most explicit waits."
            ),
        },
    ],
    "celery": [
        {
            "name": "dramatiq",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "medium",
            "advantages": [
                "Simpler API",
                "Better failure handling",
                "Less magic",
            ],
            "migration_notes": (
                "Replace `@app.task` with `@dramatiq.actor`. "
                "Use `.send()` instead of `.delay()`. Broker setup differs but is straightforward."
            ),
        },
        {
            "name": "huey",
            "reason": "better_alternative",
            "difficulty": "easy",
            "confidence": "medium",
            "advantages": [
                "Lightweight",
                "Simple setup",
                "No broker required (uses SQLite/Redis)",
            ],
            "migration_notes": (
                "Good for small-to-medium tasks. Replace @task decorator. "
                "Simpler than Celery but fewer features."
            ),
        },
    ],
    "matplotlib": [
        {
            "name": "plotly",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "Interactive charts",
                "Web-native output",
                "Dash integration",
            ],
            "migration_notes": (
                "Replace pyplot calls with plotly.express or go.Figure. "
                "Different paradigm: declarative vs imperative. Great for dashboards."
            ),
        },
        {
            "name": "seaborn",
            "reason": "better_alternative",
            "difficulty": "easy",
            "confidence": "high",
            "advantages": [
                "Statistical visualizations",
                "Beautiful defaults",
                "Built on matplotlib",
            ],
            "migration_notes": (
                "Drop-in for statistical plots. Uses matplotlib under "
                "the hood so can mix APIs. Great for data exploration."
            ),
        },
    ],
    "pandas": [
        {
            "name": "polars",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "Much faster (Rust-based)",
                "Lazy evaluation",
                "Better memory usage",
                "Multithreaded",
            ],
            "migration_notes": (
                "API differs from pandas. `pl.DataFrame` instead of "
                "`pd.DataFrame`. Use `pl.col()` expressions instead of column strings. "
                "Migration guide available at polars docs."
            ),
        },
    ],
    "twisted": [
        {
            "name": "asyncio",
            "reason": "better_alternative",
            "difficulty": "hard",
            "confidence": "high",
            "advantages": [
                "Standard library",
                "Modern async/await",
                "Larger ecosystem",
            ],
            "migration_notes": (
                "Major rewrite needed. Twisted's deferred pattern "
                "maps to async/await but the entire codebase needs restructuring. "
                "Incremental migration possible via treq/txaio bridges."
            ),
        },
    ],
    "scrapy": [
        {
            "name": "httpx+beautifulsoup4",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "medium",
            "advantages": [
                "Simpler stack",
                "Async support via httpx",
                "More flexible",
            ],
            "migration_notes": (
                "Good for small-to-medium scraping tasks. "
                "Lacks Scrapy's middleware, pipelines, and auto-throttle. "
                "Better for targeted extraction than broad crawling."
            ),
        },
    ],
    "fabric": [
        {
            "name": "invoke",
            "reason": "better_alternative",
            "difficulty": "moderate",
            "confidence": "high",
            "advantages": [
                "Modern API",
                "Better task management",
                "Same author as Fabric 2",
            ],
            "migration_notes": (
                "Fabric 2 is built on invoke. If you just need task "
                "execution without SSH, use invoke directly."
            ),
        },
    ],
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Alternative:
    """A suggested alternative package."""

    name: str
    reason: AlternativeReason
    difficulty: MigrationDifficulty
    confidence: SuggestionConfidence
    advantages: list[str] = field(default_factory=list)
    migration_notes: str = ""
    api_compatibility: float = 0.0
    popularity_proxy: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "reason": self.reason.value,
            "difficulty": self.difficulty.value,
            "confidence": self.confidence.value,
            "advantages": self.advantages,
            "migration_notes": self.migration_notes,
            "api_compatibility": self.api_compatibility,
            "popularity_proxy": self.popularity_proxy,
        }


@dataclass
class PackageSuggestion:
    """Suggestion report for a single package."""

    package: str
    current_version: str = ""
    status: HealthStatus = HealthStatus.UNKNOWN
    has_issues: bool = False
    alternatives: list[Alternative] = field(default_factory=list)
    recommendation: str = ""
    action: str = "review"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "current_version": self.current_version,
            "status": self.status.value,
            "has_issues": self.has_issues,
            "action": self.action,
            "recommendation": self.recommendation,
            "alternatives": [a.to_dict() for a in self.alternatives],
        }


@dataclass
class SuggestResult:
    """Complete suggestion report for a project."""

    project_path: str = ""
    suggestions: list[PackageSuggestion] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.suggestions)

    @property
    def migrate_count(self) -> int:
        return sum(1 for s in self.suggestions if s.action == "migrate")

    @property
    def update_count(self) -> int:
        return sum(1 for s in self.suggestions if s.action == "update")

    @property
    def review_count(self) -> int:
        return sum(1 for s in self.suggestions if s.action == "review")

    @property
    def keep_count(self) -> int:
        return sum(1 for s in self.suggestions if s.action == "keep")

    @property
    def with_alternatives(self) -> list[PackageSuggestion]:
        return [s for s in self.suggestions if s.alternatives]

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "summary": {
                "total": self.total,
                "migrate": self.migrate_count,
                "update": self.update_count,
                "review": self.review_count,
                "keep": self.keep_count,
                "with_alternatives": len(self.with_alternatives),
            },
            "suggestions": [s.to_dict() for s in self.suggestions],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def _get_known_alternatives(package_name: str) -> list[dict[str, Any]]:
    """Look up known alternatives for a package.

    Args:
        package_name: Normalized package name.

    Returns:
        List of alternative dicts from the curated database.
    """
    if package_name in _KNOWN_ALTERNATIVES:
        return _KNOWN_ALTERNATIVES[package_name]

    for key, alts in _KNOWN_ALTERNATIVES.items():
        if normalize_package_name(key) == package_name:
            return alts

    return []


def _determine_reasons(pkg: PackageReport) -> list[AlternativeReason]:
    """Determine reasons for suggesting alternatives based on package health."""
    reasons: list[AlternativeReason] = []

    if pkg.status == HealthStatus.VULNERABLE:
        reasons.append(AlternativeReason.VULNERABLE)
    if pkg.status == HealthStatus.UNMAINTAINED:
        reasons.append(AlternativeReason.UNMAINTAINED)
    if pkg.status == HealthStatus.YANKED:
        reasons.append(AlternativeReason.YANKED)
    if pkg.status == HealthStatus.REMOVED:
        reasons.append(AlternativeReason.REMOVED)
    if pkg.status == HealthStatus.OUTDATED and pkg.latest_version:
        try:
            installed = Version(pkg.installed_version)
            latest = Version(pkg.latest_version)
            if latest.major > installed.major:
                reasons.append(AlternativeReason.OUTDATED_MAJOR)
        except InvalidVersion:
            pass

    if pkg.has_license_issue:
        reasons.append(AlternativeReason.LICENSE_ISSUE)

    return reasons


def _determine_action(pkg: PackageReport, alternatives: list[Alternative]) -> str:
    """Determine the recommended action for a package."""
    if pkg.status in (HealthStatus.REMOVED, HealthStatus.YANKED):
        if alternatives:
            return "migrate"
        return "review"

    if pkg.status == HealthStatus.VULNERABLE:
        if alternatives:
            return "migrate"
        return "update"

    if pkg.status == HealthStatus.UNMAINTAINED:
        if alternatives:
            return "review"
        return "keep"

    if pkg.status == HealthStatus.OUTDATED:
        return "update"

    if alternatives and any(
        a.reason == AlternativeReason.BETTER_ALTERNATIVE
        and a.confidence == SuggestionConfidence.HIGH
        for a in alternatives
    ):
        return "review"

    return "keep"


def _build_recommendation(
    pkg: PackageReport, action: str, alternatives: list[Alternative]
) -> str:
    """Build a human-readable recommendation string."""
    if action == "keep":
        return f"{pkg.name} looks healthy - no action needed."

    if action == "update":
        if pkg.latest_version:
            return f"Update {pkg.name} from {pkg.installed_version} to {pkg.latest_version}."
        return f"Check for updates to {pkg.name}."

    if action == "migrate":
        if alternatives:
            names = ", ".join(a.name for a in alternatives[:3])
            return f"Migrate from {pkg.name} to {names}."
        return f"Consider replacing {pkg.name} - no known alternatives listed."

    # review
    if alternatives:
        best = alternatives[0]
        advantages_text = "; ".join(best.advantages[:2])
        return f"Consider {best.name} as an alternative to {pkg.name}: {advantages_text}"
    return f"Review {pkg.name} - {pkg.status.value} status detected."


def _parse_alternative_data(alt_data: dict[str, Any]) -> Alternative:
    """Parse alternative data dict into an Alternative object."""
    return Alternative(
        name=alt_data.get("name", "unknown"),
        reason=AlternativeReason(alt_data.get("reason", "better_alternative")),
        difficulty=MigrationDifficulty(alt_data.get("difficulty", "unknown")),
        confidence=SuggestionConfidence(alt_data.get("confidence", "medium")),
        advantages=alt_data.get("advantages", []),
        migration_notes=alt_data.get("migration_notes", ""),
        api_compatibility=alt_data.get("api_compatibility", 0.0),
        popularity_proxy=alt_data.get("popularity_proxy", ""),
    )


def suggest_alternatives(
    project_path: str | Path,
    scan_result: ScanResult | None = None,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
) -> SuggestResult:
    """Analyze dependencies and suggest alternatives for problematic packages.

    Args:
        project_path: Path to the project directory.
        scan_result: Pre-existing scan result (optional, scan is run if not provided).
        check_vulnerabilities: Whether to include vulnerability data.
        check_licenses: Whether to include license data.

    Returns:
        SuggestResult with alternatives and recommendations for each package.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return SuggestResult(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    if scan_result is None:
        from depcheck.scanner import scan_project

        scan_result = scan_project(
            project_path=str(project_path),
            check_vulnerabilities=check_vulnerabilities,
            check_licenses=check_licenses,
        )

    result = SuggestResult(project_path=str(project_path))
    result.errors.extend(scan_result.errors)

    for pkg in scan_result.packages:
        reasons = _determine_reasons(pkg)
        known_alt_data = _get_known_alternatives(pkg.name)
        alternatives: list[Alternative] = []

        for alt_data in known_alt_data:
            alt = _parse_alternative_data(alt_data)
            if reasons and alt.reason == AlternativeReason.BETTER_ALTERNATIVE:
                alt.reason = reasons[0]
            alternatives.append(alt)

        if reasons and not alternatives:
            if pkg.status in (HealthStatus.VULNERABLE, HealthStatus.UNMAINTAINED):
                alternatives.append(
                    Alternative(
                        name="(search PyPI)",
                        reason=reasons[0],
                        difficulty=MigrationDifficulty.UNKNOWN,
                        confidence=SuggestionConfidence.SPECULATIVE,
                        advantages=["Manual research needed"],
                        migration_notes=(
                            f"No known alternatives in depcheck's database. "
                            f"Search PyPI for '{pkg.name}' alternatives or check "
                            f"https://github.com/topics/{pkg.name}-alternative"
                        ),
                    )
                )

        action = _determine_action(pkg, alternatives)
        recommendation = _build_recommendation(pkg, action, alternatives)

        suggestion = PackageSuggestion(
            package=pkg.name,
            current_version=pkg.installed_version,
            status=pkg.status,
            has_issues=bool(reasons),
            alternatives=alternatives,
            recommendation=recommendation,
            action=action,
        )
        result.suggestions.append(suggestion)

    action_order = {"migrate": 0, "review": 1, "update": 2, "keep": 3}
    result.suggestions.sort(key=lambda s: (action_order.get(s.action, 4), s.package))

    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _status_style(status: HealthStatus) -> tuple[str, str]:
    """Get icon and color for a health status."""
    styles: dict[HealthStatus, tuple[str, str]] = {
        HealthStatus.HEALTHY: ("OK", "green"),
        HealthStatus.OUTDATED: ("UP", "yellow"),
        HealthStatus.VULNERABLE: ("!!", "red bold"),
        HealthStatus.UNMAINTAINED: ("!!", "yellow"),
        HealthStatus.YANKED: ("X", "red"),
        HealthStatus.REMOVED: ("X", "red"),
        HealthStatus.UNKNOWN: ("?", "dim"),
    }
    return styles.get(status, ("?", "white"))


def render_suggest_table(result: SuggestResult, *, console: Any = None) -> None:
    """Render suggestions as a Rich table."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    if console is None:
        console = Console()

    console.print()
    console.print(
        Panel(
            "[bold]depcheck suggest[/bold] - Dependency Alternatives & Recommendations\n"
            f"[dim]Project: {result.project_path}[/dim]",
            border_style="blue",
        )
    )

    if result.errors and not result.suggestions:
        for error in result.errors:
            console.print(f"[red]Error:[/red] {error}")
        return

    summary_parts: list[str] = []
    summary_parts.append(f"[bold]Total:[/bold] {result.total} packages")
    if result.migrate_count:
        summary_parts.append(f"[red]Migrate: {result.migrate_count}[/red]")
    if result.review_count:
        summary_parts.append(f"[yellow]Review: {result.review_count}[/yellow]")
    if result.update_count:
        summary_parts.append(f"[blue]Update: {result.update_count}[/blue]")
    if result.keep_count:
        summary_parts.append(f"[green]Keep: {result.keep_count}[/green]")
    if result.with_alternatives:
        summary_parts.append(
            f"\n[dim]{len(result.with_alternatives)} packages have alternatives available[/dim]"
        )

    console.print(Panel("\n".join(summary_parts), title="Summary", border_style="blue"))

    actionable = [s for s in result.suggestions if s.action != "keep"]
    if not actionable:
        console.print("\n[green]All dependencies look healthy - no suggestions needed.[/green]\n")
        return

    action_styles: dict[str, tuple[str, str]] = {
        "migrate": ("MIGRATE", "red bold"),
        "review": ("REVIEW", "yellow"),
        "update": ("UPDATE", "blue"),
        "keep": ("KEEP", "green"),
    }

    difficulty_styles: dict[str, str] = {
        "trivial": "green",
        "easy": "cyan",
        "moderate": "yellow",
        "hard": "red",
        "unknown": "dim",
    }

    confidence_styles: dict[str, str] = {
        "high": "green",
        "medium": "yellow",
        "low": "dim",
        "speculative": "dim italic",
    }

    table = Table(
        title="Dependency Recommendations",
        show_header=True,
        header_style="bold cyan",
        show_lines=True,
        pad_edge=False,
        expand=True,
    )
    table.add_column("Action", width=8, justify="center")
    table.add_column("Package", style="bold", min_width=18)
    table.add_column("Version", min_width=12)
    table.add_column("Status", justify="center", min_width=10)
    table.add_column("Recommendation", min_width=40)

    for s in actionable:
        label, color = action_styles.get(s.action, ("?", "white"))
        status_icon, status_color = _status_style(s.status)

        table.add_row(
            f"[{color}]{label}[/{color}]",
            f"[cyan]{s.package}[/cyan]",
            s.current_version or "-",
            f"[{status_color}]{status_icon}[/{status_color}]",
            s.recommendation,
        )

    console.print(table)

    with_alts = [s for s in actionable if s.alternatives]
    if with_alts:
        console.print()
        alt_table = Table(
            title="Alternative Packages",
            show_header=True,
            header_style="bold magenta",
            show_lines=True,
            expand=True,
        )
        alt_table.add_column("Replace", style="red", min_width=16)
        alt_table.add_column("Alternative", style="green bold", min_width=16)
        alt_table.add_column("Difficulty", justify="center", min_width=10)
        alt_table.add_column("Confidence", justify="center", min_width=10)
        alt_table.add_column("Key Advantages", min_width=35)

        for s in with_alts:
            for alt in s.alternatives:
                diff_color = difficulty_styles.get(alt.difficulty.value, "white")
                conf_color = confidence_styles.get(alt.confidence.value, "white")
                advantages = "; ".join(alt.advantages[:3])

                alt_table.add_row(
                    s.package,
                    alt.name,
                    f"[{diff_color}]{alt.difficulty.value}[/{diff_color}]",
                    f"[{conf_color}]{alt.confidence.value}[/{conf_color}]",
                    advantages,
                )

        console.print(alt_table)

    migrate_with_notes = [
        s
        for s in result.suggestions
        if s.action == "migrate" and s.alternatives and s.alternatives[0].migration_notes
    ]
    if migrate_with_notes:
        console.print()
        console.print("[bold]Migration Notes:[/bold]")
        for s in migrate_with_notes:
            best = s.alternatives[0]
            console.print(f"\n  [cyan]{s.package}[/cyan] -> [green]{best.name}[/green]:")
            console.print(f"  [dim]{best.migration_notes}[/dim]")

    console.print()


def render_suggest_json(result: SuggestResult) -> str:
    """Render suggestions as JSON."""
    return json.dumps(result.to_dict(), indent=2)
