"""Dependency isolation checker for Python projects.

Analyzes which dependencies can be safely removed without breaking
the project. Identifies:
- Unused dependencies (not imported in code)
- Transitive-only dependencies (only needed as sub-dependencies)
- Standalone packages (no other dep depends on them)
- Isolation score per package
- Suggests which packages can be safely removed
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.scanner import discover_dependencies, normalize_package_name


@dataclass
class IsolationInfo:
    """Isolation analysis for a single package."""

    name: str
    is_imported: bool = False
    import_locations: list[str] = field(default_factory=list)
    is_transitive_only: bool = False
    required_by: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    isolation_score: float = 0.0
    can_remove: bool = False
    removal_risk: str = "low"
    removal_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "is_imported": self.is_imported,
            "import_locations": self.import_locations,
            "is_transitive_only": self.is_transitive_only,
            "required_by": self.required_by,
            "requires": self.requires,
            "isolation_score": round(self.isolation_score, 2),
            "can_remove": self.can_remove,
            "removal_risk": self.removal_risk,
            "removal_note": self.removal_note,
        }


@dataclass
class IsolationReport:
    """Aggregated isolation analysis report."""

    packages: list[IsolationInfo] = field(default_factory=list)
    total_packages: int = 0
    imported_count: int = 0
    unused_count: int = 0
    transitive_only_count: int = 0
    removable_count: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "summary": {
                "total_packages": self.total_packages,
                "imported": self.imported_count,
                "unused": self.unused_count,
                "transitive_only": self.transitive_only_count,
                "removable": self.removable_count,
            },
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


# Common stdlib modules that should not be confused with third-party packages
STDLIB_MODULES = frozenset(
    {
        "abc",
        "argparse",
        "ast",
        "asyncio",
        "base64",
        "collections",
        "configparser",
        "contextlib",
        "copy",
        "csv",
        "datetime",
        "decimal",
        "difflib",
        "email",
        "enum",
        "fileinput",
        "fnmatch",
        "fractions",
        "functools",
        "glob",
        "gzip",
        "hashlib",
        "heapq",
        "html",
        "http",
        "importlib",
        "inspect",
        "io",
        "itertools",
        "json",
        "logging",
        "math",
        "multiprocessing",
        "operator",
        "os",
        "pathlib",
        "pickle",
        "platform",
        "pprint",
        "queue",
        "re",
        "secrets",
        "shutil",
        "signal",
        "socket",
        "sqlite3",
        "string",
        "struct",
        "subprocess",
        "sys",
        "tarfile",
        "tempfile",
        "textwrap",
        "threading",
        "time",
        "traceback",
        "typing",
        "unittest",
        "urllib",
        "uuid",
        "warnings",
        "xml",
        "zipfile",
    }
)

# Map of common package names to their import names
PACKAGE_TO_IMPORT = {
    "pillow": "PIL",
    "pyyaml": "yaml",
    "python-dateutil": "dateutil",
    "scikit-learn": "sklearn",
    "scikit-image": "skimage",
    "beautifulsoup4": "bs4",
    "python-dotenv": "dotenv",
    "python-multipart": "multipart",
    "opentelemetry-api": "opentelemetry",
    "google-cloud-storage": "google.cloud.storage",
    "awscli": "awscli",
    "setuptools": "setuptools",
    "pip": "pip",
    "attrs": "attr",
    "pydantic": "pydantic",
    "uvicorn": "uvicorn",
    "gunicorn": "gunicorn",
    "celery": "celery",
    "sqlalchemy": "sqlalchemy",
    "alembic": "alembic",
    "httpx": "httpx",
    "requests": "requests",
    "aiohttp": "aiohttp",
    "flask": "flask",
    "django": "django",
    "fastapi": "fastapi",
    "click": "click",
    "rich": "rich",
    "typer": "typer",
    "pytest": "pytest",
    "black": "black",
    "ruff": "ruff",
    "mypy": "mypy",
    "numpy": "numpy",
    "pandas": "pandas",
    "matplotlib": "matplotlib",
    "tornado": "tornado",
    "jinja2": "jinja2",
    "werkzeug": "werkzeug",
    "marshmallow": "marshmallow",
    "redis": "redis",
    "psycopg2": "psycopg2",
    "pymongo": "pymongo",
    "boto3": "boto3",
    "botocore": "botocore",
    "sphinx": "sphinx",
    "docutils": "docutils",
    "twine": "twine",
    "wheel": "wheel",
}


def get_import_name(package_name: str) -> str:
    """Get the Python import name for a package.

    Many packages have different import names than their pip names.
    This function handles the common mappings.

    Args:
        package_name: The normalized pip package name.

    Returns:
        The likely Python import name.
    """
    normalized = package_name.lower().replace("-", "_").replace(".", "_")
    return PACKAGE_TO_IMPORT.get(package_name, normalized)


def scan_imports_in_file(filepath: Path) -> set[str]:
    """Scan a Python file for all import statements.

    Uses AST parsing for accuracy. Handles:
    - import x
    - import x.y.z
    - from x import y
    - from x.y import z
    - try/except ImportError blocks (still counts the import)

    Args:
        filepath: Path to the Python file.

    Returns:
        Set of top-level import names found.
    """
    try:
        source = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return set()

    try:
        tree = ast.parse(source, filename=str(filepath))
    except SyntaxError:
        return set()

    imports: set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_level = alias.name.split(".")[0]
                imports.add(top_level)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_level = node.module.split(".")[0]
            imports.add(top_level)

    return imports


def scan_project_imports(project_path: Path) -> dict[str, list[str]]:
    """Scan all Python files in a project for imports.

    Returns a mapping from import name to list of files that use it.

    Args:
        project_path: Path to the project directory.

    Returns:
        Dict mapping import name to list of file paths.
    """
    import_usage: dict[str, list[str]] = {}

    for py_file in project_path.rglob("*.py"):
        # Skip common non-project directories
        rel = py_file.relative_to(project_path)
        skip_dirs = {
            ".venv",
            "venv",
            "env",
            "__pycache__",
            ".git",
            ".tox",
            "node_modules",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "dist",
            "build",
            "egg-info",
            ".eggs",
            "site-packages",
        }
        if any(part in skip_dirs for part in rel.parts):
            continue

        file_imports = scan_imports_in_file(py_file)
        for imp in file_imports:
            if imp not in import_usage:
                import_usage[imp] = []
            import_usage[imp].append(str(rel))

    return import_usage


def compute_isolation_score(
    is_imported: bool,
    is_transitive_only: bool,
    required_by_count: int,
    requires_count: int,
) -> float:
    """Compute an isolation score for a package.

    Higher scores mean the package is more isolated and easier to remove.
    Score range: 0.0 (deeply embedded) to 1.0 (completely standalone).

    Factors:
    - Not imported in code: +0.4
    - No dependents: +0.3
    - Transitive only: +0.2
    - Few own dependencies: +0.1

    Args:
        is_imported: Whether the package is imported in project code.
        is_transitive_only: Whether the package is only a transitive dep.
        required_by_count: Number of other packages that depend on this one.
        requires_count: Number of packages this one depends on.

    Returns:
        Isolation score between 0.0 and 1.0.
    """
    score = 0.0

    if not is_imported:
        score += 0.4

    if required_by_count == 0:
        score += 0.3
    elif required_by_count == 1:
        score += 0.15

    if is_transitive_only:
        score += 0.2

    if requires_count == 0:
        score += 0.1
    elif requires_count <= 2:
        score += 0.05

    return min(score, 1.0)


def assess_removal_risk(
    is_imported: bool,
    required_by_count: int,
    isolation_score: float,
) -> tuple[str, str]:
    """Assess the risk of removing a package.

    Args:
        is_imported: Whether the package is imported in code.
        required_by_count: How many packages depend on this one.
        isolation_score: The computed isolation score.

    Returns:
        Tuple of (risk_level, note).
    """
    if is_imported:
        return "high", "Package is directly imported in project code"

    if required_by_count > 0:
        return "medium", f"Required by {required_by_count} other package(s)"

    if isolation_score >= 0.7:
        return "low", "Package appears unused and has no dependents"

    if isolation_score >= 0.4:
        return "medium", "Package may be used indirectly or at runtime"

    return "high", "Package has complex dependency relationships"


def analyze_isolation(
    project_path: Path,
    dependencies: list[ParsedDependency] | None = None,
    transitive_deps: dict[str, list[str]] | None = None,
) -> IsolationReport:
    """Analyze dependency isolation for a Python project.

    Args:
        project_path: Path to the project directory.
        dependencies: Pre-parsed dependencies (discovered if None).
        transitive_deps: Optional mapping of package -> list of its sub-deps.

    Returns:
        An IsolationReport with per-package analysis.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return IsolationReport(errors=[f"Path is not a directory: {project_path}"])

    # Discover dependencies if not provided
    if dependencies is None:
        dependencies, _ = discover_dependencies(project_path)

    if not dependencies:
        return IsolationReport(errors=["No dependencies found in the project."])

    # Scan project imports
    import_usage = scan_project_imports(project_path)

    # Build transitive dependency map
    trans_map = transitive_deps or {}

    # Analyze each package
    report = IsolationReport(total_packages=len(dependencies))
    {normalize_package_name(d.name) for d in dependencies}

    for dep in dependencies:
        import_name = get_import_name(dep.name)
        is_imported = import_name in import_usage
        import_locs = import_usage.get(import_name, [])

        # Check if this package is a sub-dependency of another
        required_by: list[str] = []
        for parent, children in trans_map.items():
            if dep.name in children or normalize_package_name(dep.name) in children:
                required_by.append(parent)

        is_transitive_only = not is_imported and len(required_by) > 0
        requires = trans_map.get(dep.name, [])

        score = compute_isolation_score(
            is_imported=is_imported,
            is_transitive_only=is_transitive_only,
            required_by_count=len(required_by),
            requires_count=len(requires),
        )

        removal_risk, removal_note = assess_removal_risk(
            is_imported=is_imported,
            required_by_count=len(required_by),
            isolation_score=score,
        )

        can_remove = not is_imported and len(required_by) == 0 and score >= 0.5

        info = IsolationInfo(
            name=dep.name,
            is_imported=is_imported,
            import_locations=import_locs[:5],  # Cap at 5 for display
            is_transitive_only=is_transitive_only,
            required_by=required_by,
            requires=requires,
            isolation_score=score,
            can_remove=can_remove,
            removal_risk=removal_risk,
            removal_note=removal_note,
        )
        report.packages.append(info)

        if is_imported:
            report.imported_count += 1
        else:
            report.unused_count += 1

        if is_transitive_only:
            report.transitive_only_count += 1

        if can_remove:
            report.removable_count += 1

    # Sort: removable first, then by isolation score descending
    report.packages.sort(key=lambda p: (not p.can_remove, -p.isolation_score, p.name))

    return report


def render_isolation_table(report: IsolationReport, console: Console | None = None) -> None:
    """Render the isolation report as a Rich table.

    Args:
        report: The IsolationReport to render.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    if not report.packages:
        console.print("[yellow]No dependencies found to analyze.[/yellow]")
        return

    # Summary
    parts: list[str] = []
    parts.append(f"{report.imported_count} imported")
    if report.unused_count:
        parts.append(f"[yellow]{report.unused_count} unused[/yellow]")
    if report.transitive_only_count:
        parts.append(f"[cyan]{report.transitive_only_count} transitive-only[/cyan]")
    if report.removable_count:
        parts.append(f"[green]{report.removable_count} removable[/green]")

    summary = " • ".join(parts) + f" • {report.total_packages} total"

    console.print()
    console.print(Panel(summary, title="Dependency Isolation Analysis", border_style="blue"))

    # Main table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Package", style="cyan", min_width=20)
    table.add_column("Imported", justify="center", min_width=10)
    table.add_column("Score", justify="right", min_width=8)
    table.add_column("Risk", justify="center", min_width=8)
    table.add_column("Can Remove", justify="center", min_width=10)
    table.add_column("Required By", min_width=15)
    table.add_column("Note", min_width=25)

    for pkg in report.packages:
        imported_str = "✓ yes" if pkg.is_imported else "[dim]✗ no[/dim]"
        score_str = f"{pkg.isolation_score:.1f}"
        risk_color = {"low": "green", "medium": "yellow", "high": "red"}.get(
            pkg.removal_risk, "dim"
        )
        can_remove_str = "[green]✓ yes[/green]" if pkg.can_remove else "[dim]no[/dim]"
        req_by = ", ".join(pkg.required_by) if pkg.required_by else "-"

        table.add_row(
            pkg.name,
            imported_str,
            score_str,
            f"[{risk_color}]{pkg.removal_risk.upper()}[/{risk_color}]",
            can_remove_str,
            req_by,
            pkg.removal_note,
        )

    console.print(table)

    # Show removable packages suggestion
    removable = [p for p in report.packages if p.can_remove]
    if removable:
        console.print()
        console.print("[bold green]Removable packages (safe to remove):[/bold green]")
        names = " ".join(p.name for p in removable)
        console.print(f"  [dim]$[/dim] pip uninstall {names}")
        console.print()
        console.print(
            "[dim]Note: Review before removing — some packages may be used at runtime.[/dim]"
        )


def render_isolation_json(report: IsolationReport) -> str:
    """Render the isolation report as JSON string.

    Args:
        report: The IsolationReport to render.

    Returns:
        JSON string of the report.
    """
    import json

    return json.dumps(report.to_dict(), indent=2)
