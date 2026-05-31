"""PyPI package search for depcheck.

Search for packages on PyPI by name, keyword, or category. Provides
rich metadata including health indicators, download stats, license
info, and dependency counts. Supports filtering by license type,
maintenance status, and compatibility.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import HealthStatus
from depcheck.pypi import PyPIClient
from depcheck.scanner import normalize_package_name

# PyPI Simple API for search (XMLRPC is deprecated, we use JSON API + scraping)
PYPI_SIMPLE_URL = "https://pypi.org/simple/"
PYPI_JSON_URL = "https://pypi.org/pypi"
PYPI_STATS_URL = "https://pypistats.org/api"

REQUEST_TIMEOUT = 15.0


# ── Data models ──────────────────────────────────────────────────────────


@dataclass
class SearchResult:
    """A single package result from a PyPI search.

    Attributes:
        name: Normalized package name.
        version: Latest version string.
        summary: Short description of the package.
        license_spdx: SPDX license identifier.
        license_category: License category (permissive, copyleft, etc.).
        homepage: Project homepage URL.
        documentation: Documentation URL.
        repository: Source repository URL.
        python_requires: Python version requirement string.
        dependencies: List of direct dependency names.
        dependency_count: Number of direct dependencies.
        last_release: Date of the last release (ISO 8601).
        days_since_release: Days since last release.
        is_unmaintained: Whether the package appears unmaintained (>365 days).
        download_count: Approximate monthly downloads.
        health_status: Computed health status.
        score: Relevance/health score (0-100).
    """

    name: str = ""
    version: str = ""
    summary: str = ""
    license_spdx: str = ""
    license_category: str = "unknown"
    homepage: str = ""
    documentation: str = ""
    repository: str = ""
    python_requires: str = ""
    dependencies: list[str] = field(default_factory=list)
    dependency_count: int = 0
    last_release: str = ""
    days_since_release: int = 0
    is_unmaintained: bool = False
    download_count: int = 0
    health_status: HealthStatus = HealthStatus.UNKNOWN
    score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "summary": self.summary,
            "license": self.license_spdx,
            "license_category": self.license_category,
            "homepage": self.homepage,
            "documentation": self.documentation,
            "repository": self.repository,
            "python_requires": self.python_requires,
            "dependencies": self.dependencies,
            "dependency_count": self.dependency_count,
            "last_release": self.last_release,
            "days_since_release": self.days_since_release,
            "is_unmaintained": self.is_unmaintained,
            "download_count": self.download_count,
            "health_status": self.health_status.value,
            "score": round(self.score, 1),
        }


@dataclass
class SearchResults:
    """Aggregated search results.

    Attributes:
        query: The original search query.
        results: Ordered list of search results (by score).
        total: Number of results returned.
        errors: Any errors encountered.
    """

    query: str = ""
    results: list[SearchResult] = field(default_factory=list)
    total: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "total": self.total,
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
        }


# ── License classification helpers ──────────────────────────────────────


_LICENSE_MAP: dict[str, str] = {
    "MIT": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "BSD": "permissive",
    "Apache-2.0": "permissive",
    "Apache Software License": "permissive",
    "ISC": "permissive",
    "PSF-2.0": "permissive",
    "Python-2.0": "permissive",
    "GPL-2.0": "copyleft",
    "GPL-3.0": "copyleft",
    "GPL-2.0-only": "copyleft",
    "GPL-3.0-only": "copyleft",
    "LGPL-2.1": "copyleft",
    "LGPL-3.0": "copyleft",
    "AGPL-3.0": "copyleft",
    "MPL-2.0": "copyleft",
    "CC0-1.0": "public_domain",
    "Unlicense": "public_domain",
    "Proprietary": "proprietary",
    "Commercial": "proprietary",
}


def _classify_license(license_str: str) -> tuple[str, str]:
    """Classify a license string into SPDX ID and category.

    Args:
        license_str: Raw license string from PyPI metadata.

    Returns:
        Tuple of (spdx_id, category).
    """
    if not license_str or license_str in ("UNKNOWN", "None", ""):
        return ("", "unknown")

    # Try exact match
    if license_str in _LICENSE_MAP:
        return (license_str, _LICENSE_MAP[license_str])

    # Try case-insensitive match
    for key, cat in _LICENSE_MAP.items():
        if license_str.lower() == key.lower():
            return (key, cat)

    # Try substring match
    license_lower = license_str.lower()
    if any(kw in license_lower for kw in ("mit", "bsd", "apache", "isc")):
        return (license_str, "permissive")
    if any(kw in license_lower for kw in ("gpl", "agpl", "lgpl", "mpl", "copyleft")):
        return (license_str, "copyleft")
    if any(kw in license_lower for kw in ("cc0", "unlicense", "public domain")):
        return (license_str, "public_domain")
    if any(kw in license_lower for kw in ("proprietary", "commercial")):
        return (license_str, "proprietary")

    return (license_str, "unknown")


# ── Scoring engine ──────────────────────────────────────────────────────


def _compute_health_score(result: SearchResult) -> float:
    """Compute a health/relevance score for a search result.

    Scoring rubric (0-100):
    - Maintenance (0-30): recent releases score higher
    - Popularity (0-20): monthly download volume
    - Dependency health (0-20): fewer deps = healthier
    - License clarity (0-15): known permissive licenses score higher
    - Recency bonus (0-15): activity in last 90 days

    Args:
        result: The search result to score.

    Returns:
        Score from 0 to 100.
    """
    score = 0.0

    # Maintenance score (0-30)
    days = result.days_since_release
    if days <= 30:
        score += 30
    elif days <= 90:
        score += 25
    elif days <= 180:
        score += 18
    elif days <= 365:
        score += 10
    elif days <= 730:
        score += 5
    else:
        score += 0

    # Popularity score (0-20)
    dl = result.download_count
    if dl >= 10_000_000:
        score += 20
    elif dl >= 1_000_000:
        score += 16
    elif dl >= 100_000:
        score += 12
    elif dl >= 10_000:
        score += 8
    elif dl >= 1_000:
        score += 4
    else:
        score += 0

    # Dependency health (0-20): fewer deps = better
    dep_count = result.dependency_count
    if dep_count == 0:
        score += 20
    elif dep_count <= 3:
        score += 16
    elif dep_count <= 7:
        score += 12
    elif dep_count <= 15:
        score += 6
    else:
        score += 0

    # License clarity (0-15)
    cat = result.license_category
    if cat in ("permissive", "public_domain"):
        score += 15
    elif cat == "copyleft":
        score += 8
    elif cat == "unknown":
        score += 2
    else:
        score += 0

    # Recency bonus (0-15) for very recent activity
    if days <= 7:
        score += 15
    elif days <= 30:
        score += 10
    elif days <= 90:
        score += 5

    return min(100.0, score)


def _compute_health_status(result: SearchResult) -> HealthStatus:
    """Compute health status based on package metadata.

    Args:
        result: The search result to evaluate.

    Returns:
        HealthStatus enum value.
    """
    if result.is_unmaintained:
        return HealthStatus.UNMAINTAINED
    if result.days_since_release <= 90:
        return HealthStatus.HEALTHY
    if result.days_since_release <= 365:
        return HealthStatus.OUTDATED
    return HealthStatus.UNMAINTAINED


# ── Search implementation ───────────────────────────────────────────────


def _fetch_package_detail(
    pypi_client: PyPIClient,
    package_name: str,
) -> SearchResult | None:
    """Fetch detailed metadata for a single package.

    Args:
        pypi_client: PyPI API client.
        package_name: Package name to look up.

    Returns:
        SearchResult or None if package not found.
    """
    info = pypi_client.get_package_info(package_name)
    if info is None:
        return None

    pkg_info = info.get("info", {})
    result = SearchResult(name=normalize_package_name(package_name))

    # Basic metadata
    result.version = pkg_info.get("version", "")
    result.summary = pkg_info.get("summary", "") or ""
    result.homepage = pkg_info.get("home_page", "") or ""
    result.documentation = pkg_info.get("doc_url", "") or ""
    result.repository = pkg_info.get("project_urls", {}).get("Source", "") or ""
    if not result.repository:
        result.repository = pkg_info.get("project_urls", {}).get("Repository", "") or ""
    if not result.repository:
        result.repository = pkg_info.get("project_urls", {}).get("GitHub", "") or ""
    result.python_requires = pkg_info.get("requires_python", "") or ""

    # License
    raw_license = pkg_info.get("license", "") or ""
    classifiers = pkg_info.get("classifiers", []) or []
    # Try to extract license from classifiers
    for cls in classifiers:
        if cls.startswith("License ::"):
            parts = cls.split("::")
            if len(parts) >= 3:
                classifier_license = parts[-1].strip()
                if classifier_license not in (
                    "OSI Approved",
                    "Other/Proprietary",
                ):
                    raw_license = classifier_license
                    break
    result.license_spdx, result.license_category = _classify_license(raw_license)

    # Dependencies
    requires_dist = pkg_info.get("requires_dist", []) or []
    deps: list[str] = []
    for req in requires_dist:
        req = req.strip()
        if not req:
            continue
        # Skip extras and platform markers
        if ";" in req:
            _, marker = req.split(";", 1)
            marker = marker.strip().lower()
            if any(
                kw in marker
                for kw in (
                    "sys_platform",
                    "platform_system",
                    "platform_machine",
                    "python_version",
                    "implementation_name",
                    "extra ==",
                )
            ):
                continue
        # Extract package name
        import re

        match = re.match(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)", req)
        if match:
            deps.append(normalize_package_name(match.group(1)))

    result.dependencies = deps
    result.dependency_count = len(deps)

    # Last release date
    releases = info.get("releases", {})
    latest_dates: list[datetime] = []
    for ver, files in releases.items():
        for file_info in files:
            upload_time = file_info.get("upload_time_iso_8601")
            if upload_time:
                try:
                    dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                    latest_dates.append(dt)
                except (ValueError, TypeError):
                    continue

    if latest_dates:
        last_dt = max(latest_dates)
        result.last_release = last_dt.strftime("%Y-%m-%d")
        result.days_since_release = (datetime.now(tz=last_dt.tzinfo) - last_dt).days
        result.is_unmaintained = result.days_since_release > 365

    # Health scoring
    result.health_status = _compute_health_status(result)
    result.score = _compute_health_score(result)

    return result


def search_packages(
    query: str,
    limit: int = 10,
    license_filter: str | None = None,
    python_version: str | None = None,
    min_score: float = 0.0,
) -> SearchResults:
    """Search for packages on PyPI matching the query.

    Uses PyPI's JSON API to look up packages by exact or partial name
    match. For each match, fetches full metadata and computes a health
    score.

    Args:
        query: Search query (package name or substring).
        limit: Maximum number of results to return.
        license_filter: Filter by license category (permissive, copyleft, etc.).
        python_version: Filter by Python version compatibility.
        min_score: Minimum health score to include (0-100).

    Returns:
        SearchResults with ranked package results.
    """
    results = SearchResults(query=query)
    query_lower = query.lower().replace("-", "-").replace("_", "-").replace(".", "-")

    # Use PyPI's simple index to find candidate package names
    candidates: list[str] = []

    # First, try exact match
    candidates.append(query_lower)

    # Then try common variations
    for prefix in ("", "python-", "py"):
        candidates.append(normalize_package_name(f"{prefix}{query}"))

    # Fetch PyPI simple index to find close matches
    try:
        client = httpx.Client(timeout=REQUEST_TIMEOUT, follow_redirects=True)
        resp = client.get(PYPI_SIMPLE_URL)
        client.close()
        if resp.status_code == 200:
            import re

            # Parse package names from simple index HTML
            names = re.findall(r'<a href="/simple/([^/]+)/">', resp.text)
            for name in names:
                norm_name = normalize_package_name(name)
                if query_lower in norm_name or norm_name.startswith(query_lower):
                    if norm_name not in candidates:
                        candidates.append(norm_name)
    except Exception:
        pass  # Non-critical: simple index may be unavailable

    # Deduplicate candidates
    seen: set[str] = set()
    unique_candidates: list[str] = []
    for c in candidates:
        norm = normalize_package_name(c)
        if norm not in seen:
            seen.add(norm)
            unique_candidates.append(norm)

    # Fetch details for each candidate
    search_results: list[SearchResult] = []
    with PyPIClient() as pypi_client:
        for candidate in unique_candidates[:50]:  # Limit API calls
            try:
                result = _fetch_package_detail(pypi_client, candidate)
                if result is not None:
                    search_results.append(result)
            except Exception:
                continue  # Skip packages that fail to fetch

    # Apply filters
    filtered: list[SearchResult] = []
    for r in search_results:
        if license_filter and r.license_category != license_filter.lower():
            continue
        if python_version and r.python_requires:
            # Simple check: does the requires_python contain the requested version?
            if python_version not in r.python_requires:
                # More nuanced check for version ranges
                try:
                    from packaging.specifiers import SpecifierSet

                    spec = SpecifierSet(r.python_requires)
                    from packaging.version import Version

                    if Version(python_version) not in spec:
                        continue
                except Exception:
                    continue  # Can't verify, skip
        if r.score < min_score:
            continue
        filtered.append(r)

    # Sort by score (descending)
    filtered.sort(key=lambda r: r.score, reverse=True)

    # Apply limit
    results.results = filtered[:limit]
    results.total = len(results.results)

    return results


def search_by_category(
    category: str,
    limit: int = 10,
    min_score: float = 0.0,
) -> SearchResults:
    """Search for popular packages in a given category.

    Searches PyPI for well-known packages in common categories like
    'web', 'data', 'testing', 'cli', 'database', 'security'.

    Args:
        category: Package category (web, data, testing, cli, database, security).
        limit: Maximum number of results.
        min_score: Minimum health score to include.

    Returns:
        SearchResults with ranked results.
    """
    # Curated list of popular packages by category
    _CATEGORY_PACKAGES: dict[str, list[str]] = {
        "web": [
            "flask", "django", "fastapi", "starlette", "aiohttp",
            "sanic", "tornado", "bottle", "pyramid", "quart",
            "httpx", "requests", "uvicorn", "gunicorn", "werkzeug",
        ],
        "data": [
            "pandas", "numpy", "polars", "dask", "pyarrow",
            "scipy", "matplotlib", "seaborn", "plotly", "altair",
            "sqlalchemy", "petl", "agate", "tablib", "openpyxl",
        ],
        "testing": [
            "pytest", "unittest2", "nose2", "hypothesis", "faker",
            "pytest-cov", "pytest-mock", "responses", "freezegun",
            "coverage", "tox", "nox", "ward", "mutmut",
        ],
        "cli": [
            "click", "typer", "argparse", "rich", "textual",
            "prompt-toolkit", "docopt", "fire", "cement", "cleo",
        ],
        "database": [
            "sqlalchemy", "alembic", "psycopg2", "pymongo", "redis",
            "sqlite-utils", "dataset", "peewee", "tortoise-orm", "orm",
        ],
        "security": [
            "cryptography", "pyjwt", "passlib", "bcrypt", "argon2-cffi",
            "pyotp", "certifi", "oauthlib", "pyopenssl", "paramiko",
        ],
        "ml": [
            "scikit-learn", "tensorflow", "torch", "xgboost", "lightgbm",
            "catboost", "transformers", "jax", "keras", "onnxruntime",
        ],
        "devtools": [
            "black", "ruff", "mypy", "pylint", "flake8",
            "isort", "pyright", "pre-commit", "tox", "setuptools",
        ],
    }

    category_lower = category.lower()
    packages = _CATEGORY_PACKAGES.get(category_lower, [])

    if not packages:
        return SearchResults(
            query=f"category:{category}",
            errors=[f"Unknown category '{category}'. Choose from: web, data, testing, cli, database, security, ml, devtools"],
        )

    results = SearchResults(query=f"category:{category}")

    with PyPIClient() as pypi_client:
        for pkg_name in packages:
            try:
                result = _fetch_package_detail(pypi_client, pkg_name)
                if result is not None and result.score >= min_score:
                    results.results.append(result)
            except Exception:
                continue

    results.results.sort(key=lambda r: r.score, reverse=True)
    results.results = results.results[:limit]
    results.total = len(results.results)

    return results


# ── Rendering ────────────────────────────────────────────────────────────


def render_search_table(results: SearchResults, console: Console | None = None) -> None:
    """Render search results as a Rich table.

    Args:
        results: The search results to render.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    if results.errors and not results.results:
        for error in results.errors:
            console.print(f"[red]Error:[/red] {error}")
        return

    console.print()
    console.print(
        Panel(
            f"[bold]depcheck search[/bold] — {results.total} result{'s' if results.total != 1 else ''} "
            f"for '[cyan]{results.query}[/cyan]'",
            border_style="blue",
        )
    )

    if not results.results:
        console.print("[dim]No packages found. Try a different query.[/dim]")
        return

    table = Table(
        title="Package Search Results",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        pad_edge=False,
        expand=True,
    )

    table.add_column("#", width=3, justify="right")
    table.add_column("Score", width=6, justify="center")
    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Version", min_width=10)
    table.add_column("License", min_width=12)
    table.add_column("Deps", width=5, justify="right")
    table.add_column("Last Release", min_width=12)
    table.add_column("Status", width=8, justify="center")
    table.add_column("Summary", min_width=30, no_wrap=False)

    status_icons = {
        HealthStatus.HEALTHY: ("✓", "green"),
        HealthStatus.OUTDATED: ("↑", "yellow"),
        HealthStatus.UNMAINTAINED: ("⚠", "red"),
        HealthStatus.UNKNOWN: ("?", "dim"),
    }

    for i, r in enumerate(results.results, 1):
        # Score color
        if r.score >= 80:
            score_str = f"[green]{r.score:.0f}[/green]"
        elif r.score >= 50:
            score_str = f"[yellow]{r.score:.0f}[/yellow]"
        else:
            score_str = f"[red]{r.score:.0f}[/red]"

        # License color
        lic_color = "green" if r.license_category == "permissive" else (
            "yellow" if r.license_category == "copyleft" else "white"
        )
        lic_str = r.license_spdx or "Unknown"

        # Status icon
        icon, color = status_icons.get(r.health_status, ("?", "dim"))

        # Truncate summary
        summary = r.summary[:80] + ("..." if len(r.summary) > 80 else "")

        table.add_row(
            str(i),
            score_str,
            f"[cyan]{r.name}[/cyan]",
            r.version,
            f"[{lic_color}]{lic_str}[/{lic_color}]",
            str(r.dependency_count),
            r.last_release or "—",
            f"[{color}]{icon}[/{color}]",
            summary,
        )

    console.print(table)

    # Detail for top result
    if results.results:
        top = results.results[0]
        console.print()
        console.print(f"[bold]Top result:[/bold] [cyan]{top.name}[/cyan] v{top.version}")
        if top.repository:
            console.print(f"  [dim]Repo: {top.repository}[/dim]")
        if top.homepage:
            console.print(f"  [dim]Home: {top.homepage}[/dim]")
        if top.documentation:
            console.print(f"  [dim]Docs: {top.documentation}[/dim]")
        if top.dependencies:
            console.print(f"  [dim]Deps: {', '.join(top.dependencies[:10])}[/dim]")
            if len(top.dependencies) > 10:
                console.print(f"  [dim]       ... and {len(top.dependencies) - 10} more[/dim]")
        if top.python_requires:
            console.print(f"  [dim]Python: {top.python_requires}[/dim]")
        console.print()


def render_search_json(results: SearchResults) -> str:
    """Render search results as JSON string.

    Args:
        results: The search results to render.

    Returns:
        JSON string.
    """
    return json.dumps(results.to_dict(), indent=2)
