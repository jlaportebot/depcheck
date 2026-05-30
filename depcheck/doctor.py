"""Dependency doctor — diagnose and fix dependency issues for depcheck.

Runs a comprehensive diagnostic on the project environment and dependency
configuration, detecting common problems and suggesting fixes:

- Python version compatibility
- Unpinned/loose version specifiers
- Missing dependency files
- Conflicting requirements
- Virtual environment health
- Pip/package manager issues
- Dependency file formatting issues
- Import resolution (declared but not installed, installed but not declared)
"""

from __future__ import annotations

import enum
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.scanner import discover_dependencies, normalize_package_name


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(enum.Enum):
    """Severity level for a diagnostic finding."""

    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class Category(enum.Enum):
    """Category for a diagnostic finding."""

    VERSION = "version"
    CONFIGURATION = "configuration"
    ENVIRONMENT = "environment"
    CONSISTENCY = "consistency"
    SECURITY = "security"
    FORMATTING = "formatting"


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single diagnostic finding."""

    category: Category
    severity: Severity
    title: str
    description: str
    package: str | None = None
    fix: str | None = None
    file_path: str | None = None
    line_number: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "package": self.package,
            "fix": self.fix,
            "file_path": self.file_path,
            "line_number": self.line_number,
        }


@dataclass
class DoctorReport:
    """Aggregated diagnostic report."""

    project_path: str
    findings: list[Finding] = field(default_factory=list)
    checks_run: int = 0
    python_version: str = ""
    pip_version: str = ""
    venv_active: bool = False
    venv_path: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def has_critical(self) -> bool:
        return self.critical_count > 0

    @property
    def is_healthy(self) -> bool:
        return self.critical_count == 0 and self.warning_count == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "summary": {
                "checks_run": self.checks_run,
                "critical_count": self.critical_count,
                "warning_count": self.warning_count,
                "info_count": self.info_count,
                "is_healthy": self.is_healthy,
                "python_version": self.python_version,
                "pip_version": self.pip_version,
                "venv_active": self.venv_active,
                "venv_path": self.venv_path,
            },
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Diagnostic checks
# ---------------------------------------------------------------------------


def _check_python_version(
    project_path: Path, findings: list[Finding]
) -> None:
    """Check Python version compatibility with declared requires-python."""
    pyproject = project_path / "pyproject.toml"
    if not pyproject.is_file():
        return

    try:
        content = pyproject.read_text(encoding="utf-8")
    except OSError:
        return

    # Look for requires-python
    match = re.search(r'requires-python\s*=\s*["\']([^"\']+)["\']', content)
    if not match:
        findings.append(
            Finding(
                category=Category.CONFIGURATION,
                severity=Severity.INFO,
                title="No requires-python declared",
                description="pyproject.toml does not specify requires-python. "
                "Consider adding [project] requires-python to declare compatibility.",
                fix="Add requires-python = '>=3.9' to [project] in pyproject.toml",
                file_path=str(pyproject),
            )
        )
        return

    requires_python = match.group(1)
    current = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"

    from packaging.specifiers import SpecifierSet

    try:
        spec = SpecifierSet(requires_python)
        if current not in spec:
            findings.append(
                Finding(
                    category=Category.ENVIRONMENT,
                    severity=Severity.CRITICAL,
                    title="Python version incompatible",
                    description=f"Current Python {current} does not satisfy "
                    f"requires-python '{requires_python}'.",
                    fix=f"Switch to a Python version matching '{requires_python}'",
                )
            )
    except Exception:
        findings.append(
            Finding(
                category=Category.CONFIGURATION,
                severity=Severity.WARNING,
                title="Invalid requires-python specifier",
                description=f"requires-python '{requires_python}' could not be parsed.",
                file_path=str(pyproject),
            )
        )


def _check_venv(findings: list[Finding]) -> tuple[bool, str | None, str]:
    """Check if a virtual environment is active."""
    in_venv = hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    )
    venv_path = sys.prefix if in_venv else None

    # Get pip version
    pip_version = "unknown"
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            # pip X.Y.Z from /path/...
            match = re.match(r"pip\s+(\S+)", result.stdout)
            if match:
                pip_version = match.group(1)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    if not in_venv:
        findings.append(
            Finding(
                category=Category.ENVIRONMENT,
                severity=Severity.WARNING,
                title="No virtual environment active",
                description="Running without a virtual environment. Dependencies "
                "are installed globally, which can cause conflicts and "
                "make reproducibility harder.",
                fix="Create and activate a virtual environment: "
                "python -m venv .venv && source .venv/bin/activate",
            )
        )

    return in_venv, venv_path, pip_version


def _check_unpinned_deps(
    project_path: Path, findings: list[Finding]
) -> None:
    """Check for unpinned or loosely specified dependencies."""
    dependencies, _ = discover_dependencies(project_path)

    unpinned = []
    loose = []

    for dep in dependencies:
        if dep.specifier is None and dep.version is None:
            unpinned.append(dep)
        elif dep.specifier and not dep.specifier.startswith("=="):
            # Loose specifier like >=, ~=, !=
            if dep.specifier.startswith("=="):
                continue
            loose.append(dep)

    for dep in unpinned:
        findings.append(
            Finding(
                category=Category.SECURITY,
                severity=Severity.CRITICAL,
                title="Unpinned dependency",
                description=f"'{dep.name}' has no version specifier. This means "
                f"any version could be installed, leading to unpredictable builds.",
                package=dep.name,
                fix=f"Pin to a specific version: {dep.name}==X.Y.Z",
            )
        )

    for dep in loose:
        spec_type = "compatible" if dep.specifier.startswith("~=") else "minimum"
        findings.append(
            Finding(
                category=Category.SECURITY,
                severity=Severity.WARNING,
                title=f"Loosely pinned dependency ({spec_type})",
                description=f"'{dep.name}' uses '{dep.specifier}' which allows "
                f"a range of versions. Consider pinning to an exact version "
                f"in your lockfile for reproducible builds.",
                package=dep.name,
                fix=f"Consider using {dep.name}==X.Y.Z in your lockfile",
            )
        )


def _check_dep_files(
    project_path: Path, findings: list[Finding]
) -> None:
    """Check for missing or problematic dependency files."""
    has_req = (project_path / "requirements.txt").is_file()
    has_pyproject = (project_path / "pyproject.toml").is_file()
    has_pipfile = (project_path / "Pipfile").is_file()
    has_setup = (project_path / "setup.py").is_file()
    has_setup_cfg = (project_path / "setup.cfg").is_file()

    if not has_req and not has_pyproject and not has_pipfile and not has_setup:
        findings.append(
            Finding(
                category=Category.CONFIGURATION,
                severity=Severity.CRITICAL,
                title="No dependency files found",
                description="No requirements.txt, pyproject.toml, Pipfile, "
                "setup.py, or setup.cfg found. Dependencies cannot be tracked.",
                fix="Create a requirements.txt or pyproject.toml with your "
                "project dependencies.",
            )
        )

    # Check for requirements.txt without pinned versions
    if has_req:
        req_path = project_path / "requirements.txt"
        try:
            content = req_path.read_text(encoding="utf-8")
            lines = content.strip().splitlines()
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                    continue
                match = re.match(
                    r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)", stripped
                )
                if match and "==" not in stripped:
                    pkg_name = match.group(1)
                    findings.append(
                        Finding(
                            category=Category.SECURITY,
                            severity=Severity.WARNING,
                            title="Unpinned requirement in requirements.txt",
                            description=f"'{pkg_name}' in requirements.txt is not "
                            f"pinned with ==. Line: {stripped}",
                            package=pkg_name,
                            file_path=str(req_path),
                            line_number=i,
                            fix=f"Pin with: {pkg_name}==X.Y.Z",
                        )
                    )
        except OSError:
            pass

    # Check for deprecated setup.py without pyproject.toml
    if has_setup and not has_pyproject:
        findings.append(
            Finding(
                category=Category.CONFIGURATION,
                severity=Severity.INFO,
                title="Using legacy setup.py without pyproject.toml",
                description="setup.py is the legacy packaging format. Consider "
                "migrating to pyproject.toml for modern Python packaging.",
                fix="Create a pyproject.toml with [project] section and "
                "migrate metadata from setup.py.",
            )
        )

    # Check for Pipfile without lock
    if has_pipfile:
        has_lock = (project_path / "Pipfile.lock").is_file()
        if not has_lock:
            findings.append(
                Finding(
                    category=Category.CONSISTENCY,
                    severity=Severity.WARNING,
                    title="Pipfile without Pipfile.lock",
                    description="Pipfile exists but Pipfile.lock is missing. "
                    "This means dependencies are not pinned to exact versions.",
                    fix="Run 'pipenv lock' to generate Pipfile.lock.",
                )
            )

    # Check for pyproject.toml without lockfile
    if has_pyproject:
        has_poetry_lock = (project_path / "poetry.lock").is_file()
        has_req_lock = any(
            p.name.startswith("requirements") and "lock" in p.name.lower()
            for p in project_path.iterdir()
            if p.is_file()
        )
        # Check if poetry section exists in pyproject.toml
        has_poetry = False
        try:
            content = (project_path / "pyproject.toml").read_text(encoding="utf-8")
            has_poetry = "[tool.poetry]" in content
        except OSError:
            pass

        if has_poetry and not has_poetry_lock:
            findings.append(
                Finding(
                    category=Category.CONSISTENCY,
                    severity=Severity.WARNING,
                    title="Poetry project without poetry.lock",
                    description="pyproject.toml uses Poetry but poetry.lock is missing. "
                    "This means exact dependency versions are not committed.",
                    fix="Run 'poetry lock' to generate poetry.lock.",
                )
            )


def _check_import_consistency(
    project_path: Path, findings: list[Finding]
) -> None:
    """Check for packages that are imported but not declared, or declared but unused."""
    dependencies, _ = discover_dependencies(project_path)
    declared_names = {normalize_package_name(dep.name) for dep in dependencies}

    # Common stdlib modules that shouldn't be in requirements
    STDLIB_MODULES = {
        "os", "sys", "re", "json", "math", "datetime", "pathlib",
        "collections", "itertools", "functools", "typing", "dataclasses",
        "enum", "abc", "io", "hashlib", "subprocess", "shutil",
        "tempfile", "logging", "unittest", "argparse", "configparser",
        "csv", "xml", "html", "email", "urllib", "http", "ftplib",
        "smtplib", "socket", "ssl", "select", "signal", "mmap",
        "struct", "codecs", "unicodedata", "locale", "gettext",
        "threading", "multiprocessing", "queue", "asyncio", "contextlib",
        "importlib", "pkgutil", "inspect", "ast", "dis", "gc",
        "copy", "pickle", "shelve", "sqlite3", "zlib", "gzip",
        "bz2", "lzma", "zipfile", "tarfile", "base64", "binascii",
        "operator", "numbers", "decimal", "fractions", "random",
        "statistics", "time", "calendar", "heapq", "bisect",
        "array", "weakref", "types", "pprint", "textwrap",
        "string", "difflib", "fnmatch", "glob", "stat", "fileinput",
    }

    # Map import names to package names for common packages
    IMPORT_TO_PACKAGE: dict[str, str] = {
        "cv2": "opencv-python",
        "PIL": "pillow",
        "sklearn": "scikit-learn",
        "skimage": "scikit-image",
        "git": "gitpython",
        "yaml": "pyyaml",
        "serial": "pyserial",
        "usb": "pyusb",
        "wx": "wxpython",
        "Crypto": "pycryptodome",
        "OpenSSL": "pyopenssl",
        "lxml": "lxml",
        "dateutil": "python-dateutil",
        "jwt": "pyjwt",
        "magic": "python-magic",
        "gi": "pygobject",
        "attr": "attrs",
        "sklearn": "scikit-learn",
        "Bio": "biopython",
        "tifffile": "tifffile",
    }

    # Scan Python files for import statements
    imported_packages: set[str] = set()
    py_files = list(project_path.rglob("*.py"))

    # Limit scan to avoid excessive I/O
    max_files = 100
    for py_file in py_files[:max_files]:
        # Skip venv, .git, __pycache__, etc.
        parts = py_file.parts
        if any(
            skip in parts
            for skip in [".venv", "venv", ".git", "__pycache__", "node_modules", ".tox"]
        ):
            continue

        try:
            content = py_file.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue

        for line in content.splitlines():
            stripped = line.strip()
            # Match "import X" and "from X import Y"
            match = re.match(
                r"^(?:from\s+(\S+)\s+import|import\s+([a-zA-Z_][a-zA-Z0-9_.]*))",
                stripped,
            )
            if not match:
                continue

            import_name = (match.group(1) or match.group(2)).split(".")[0]

            # Skip stdlib
            if import_name in STDLIB_MODULES:
                continue

            # Resolve to package name
            pkg_name = IMPORT_TO_PACKAGE.get(import_name, import_name)
            normalized = normalize_package_name(pkg_name)
            imported_packages.add(normalized)

    # Find packages imported but not declared
    undeclared = imported_packages - declared_names - STDLIB_MODULES
    # Filter out known project-local modules
    project_modules = {
        normalize_package_name(p.stem)
        for p in project_path.rglob("*.py")
        if not any(
            skip in p.parts
            for skip in [".venv", "venv", ".git", "__pycache__", "node_modules", ".tox"]
        )
    }
    undeclared -= project_modules

    for pkg in sorted(undeclared)[:10]:  # Limit to 10 findings
        findings.append(
            Finding(
                category=Category.CONSISTENCY,
                severity=Severity.WARNING,
                title="Imported but not declared",
                description=f"'{pkg}' is imported in your code but not declared "
                f"in your dependency files. It may be a transitive dependency "
                f"or an undeclared direct dependency.",
                package=pkg,
                fix=f"Add '{pkg}' to your requirements.txt or pyproject.toml",
            )
        )

    # Find declared but potentially unused (only if we scanned code)
    if py_files:
        unused = declared_names - imported_packages - project_modules
        # Filter out packages that are typically not directly imported
        meta_packages = {
            "pytest", "ruff", "black", "mypy", "flake8", "pylint",
            "isort", "autopep8", "coverage", "pytest-cov", "pip",
            "setuptools", "wheel", "build", "twine", "hatchling",
            "hatch", "tox", "nox", "pre-commit",
        }
        unused -= meta_packages

        for pkg in sorted(unused)[:5]:
            findings.append(
                Finding(
                    category=Category.CONSISTENCY,
                    severity=Severity.INFO,
                    title="Declared but not directly imported",
                    description=f"'{pkg}' is declared in your dependency files but "
                    f"not directly imported in scanned Python files. It may be a "
                    f"transitive dependency or a dev tool.",
                    package=pkg,
                )
            )


def _check_formatting(
    project_path: Path, findings: list[Finding]
) -> None:
    """Check dependency file formatting issues."""
    req_file = project_path / "requirements.txt"
    if req_file.is_file():
        try:
            content = req_file.read_text(encoding="utf-8")
        except OSError:
            return

        lines = content.splitlines()

        # Check for mixed case package names
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                continue
            match = re.match(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)", stripped)
            if match:
                pkg_name = match.group(1)
                if pkg_name != pkg_name.lower():
                    findings.append(
                        Finding(
                            category=Category.FORMATTING,
                            severity=Severity.INFO,
                            title="Mixed-case package name",
                            description=f"'{pkg_name}' uses mixed case. PEP 503 "
                            f"recommends lowercase package names.",
                            package=pkg_name,
                            file_path=str(req_file),
                            line_number=i,
                            fix=f"Use lowercase: {pkg_name.lower()}",
                        )
                    )

        # Check for trailing whitespace
        for i, line in enumerate(lines, 1):
            if line != line.rstrip():
                findings.append(
                    Finding(
                        category=Category.FORMATTING,
                        severity=Severity.INFO,
                        title="Trailing whitespace",
                        description=f"Line {i} in requirements.txt has trailing whitespace.",
                        file_path=str(req_file),
                        line_number=i,
                        fix="Remove trailing whitespace.",
                    )
                )
                break  # Only report once

        # Check for no newline at end of file
        if content and not content.endswith("\n"):
            findings.append(
                Finding(
                    category=Category.FORMATTING,
                    severity=Severity.INFO,
                    title="No newline at end of file",
                    description="requirements.txt does not end with a newline. "
                    "Some tools expect this.",
                    file_path=str(req_file),
                    fix="Add a trailing newline to requirements.txt.",
                )
            )

    # Check pyproject.toml formatting
    pyproject = project_path / "pyproject.toml"
    if pyproject.is_file():
        try:
            content = pyproject.read_text(encoding="utf-8")
        except OSError:
            return

        # Check for duplicate [project.dependencies] keys
        if "[project.dependencies]" in content or "[tool.poetry.dependencies]" in content:
            dep_lines: dict[str, int] = {}
            for i, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("["):
                    continue
                match = re.match(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*=", stripped)
                if not match:
                    match = re.match(
                        r'^([a-zA-Z0-9][a-zA-Z0-9._-]*)\s*=\s*["\']', stripped
                    )
                if match:
                    name = normalize_package_name(match.group(1))
                    if name in dep_lines:
                        findings.append(
                            Finding(
                                category=Category.CONSISTENCY,
                                severity=Severity.WARNING,
                                title="Duplicate dependency entry",
                                description=f"'{name}' appears multiple times in "
                                f"pyproject.toml (lines {dep_lines[name]} and {i}).",
                                package=name,
                                file_path=str(pyproject),
                                line_number=i,
                                fix=f"Remove duplicate entry for '{name}'.",
                            )
                        )
                    else:
                        dep_lines[name] = i


def _check_conflicts(
    project_path: Path, findings: list[Finding]
) -> None:
    """Check for conflicting version requirements across dependency files."""
    dependencies, files_scanned = discover_dependencies(project_path)

    # Track which version each package requires per file
    pkg_versions: dict[str, list[tuple[str, str | None]]] = {}
    for dep in dependencies:
        if dep.name not in pkg_versions:
            pkg_versions[dep.name] = []
        # We don't have file-level granularity from discover_dependencies,
        # so we just check for duplicate packages with different versions
        pkg_versions[dep.name].append((dep.specifier or "any", dep.version))

    for name, specs in pkg_versions.items():
        if len(specs) <= 1:
            continue
        # Check if specs are contradictory
        unique_specs = set(s[0] for s in specs)
        if len(unique_specs) > 1:
            spec_str = ", ".join(s[0] for s in specs)
            findings.append(
                Finding(
                    category=Category.CONSISTENCY,
                    severity=Severity.WARNING,
                    title="Multiple version specifiers",
                    description=f"'{name}' has conflicting specifiers: {spec_str}. "
                    f"This may cause installation issues.",
                    package=name,
                    fix=f"Unify the version specifier for '{name}' across "
                    f"all dependency files.",
                )
            )


# ---------------------------------------------------------------------------
# Main doctor function
# ---------------------------------------------------------------------------


def run_doctor(project_path: str) -> DoctorReport:
    """Run comprehensive diagnostics on a project's dependency setup.

    Args:
        project_path: Path to the project directory.

    Returns:
        A DoctorReport with all findings.
    """
    project_path_obj = Path(project_path).resolve()

    if not project_path_obj.is_dir():
        return DoctorReport(
            project_path=str(project_path_obj),
            errors=[f"Path is not a directory: {project_path_obj}"],
        )

    report = DoctorReport(project_path=str(project_path_obj))

    # Check virtual environment
    venv_active, venv_path, pip_version = _check_venv(report.findings)
    report.venv_active = venv_active
    report.venv_path = venv_path
    report.pip_version = pip_version
    report.python_version = (
        f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    )
    report.checks_run += 1

    # Check Python version compatibility
    _check_python_version(project_path_obj, report.findings)
    report.checks_run += 1

    # Check dependency files
    _check_dep_files(project_path_obj, report.findings)
    report.checks_run += 1

    # Check for unpinned dependencies
    _check_unpinned_deps(project_path_obj, report.findings)
    report.checks_run += 1

    # Check for conflicting requirements
    _check_conflicts(project_path_obj, report.findings)
    report.checks_run += 1

    # Check import consistency
    _check_import_consistency(project_path_obj, report.findings)
    report.checks_run += 1

    # Check formatting
    _check_formatting(project_path_obj, report.findings)
    report.checks_run += 1

    return report


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _severity_icon(severity: Severity) -> str:
    """Return a Rich-formatted icon for a severity level."""
    icons = {
        Severity.CRITICAL: "[red]✗ CRITICAL[/red]",
        Severity.WARNING: "[yellow]⚠ WARNING[/yellow]",
        Severity.INFO: "[blue]ℹ INFO[/blue]",
    }
    return icons.get(severity, "[dim]? UNKNOWN[/dim]")


def render_doctor_table(
    report: DoctorReport, console: Console | None = None
) -> None:
    """Render doctor report as a Rich table."""
    if console is None:
        console = Console()

    console.print()
    console.print(f"[bold]Dependency Doctor: {report.project_path}[/bold]")
    console.print()

    # Environment info
    env_table = Table(title="Environment", show_header=True, header_style="bold cyan")
    env_table.add_column("Property", style="bold")
    env_table.add_column("Value")

    env_table.add_row("Python", report.python_version)
    env_table.add_row("pip", report.pip_version)
    venv_status = (
        f"[green]Yes[/green] ({report.venv_path})"
        if report.venv_active
        else "[red]No[/red]"
    )
    env_table.add_row("Virtual Environment", venv_status)
    env_table.add_row("Checks Run", str(report.checks_run))

    console.print(env_table)
    console.print()

    # Summary
    if report.is_healthy:
        console.print("[bold green]✓ All clear — no dependency issues found![/bold green]")
    else:
        console.print(
            f"[bold]Findings: {report.critical_count} critical, "
            f"{report.warning_count} warnings, {report.info_count} info[/bold]"
        )
    console.print()

    # Findings by severity
    if not report.findings:
        return

    findings_table = Table(
        title="Findings",
        show_header=True,
        header_style="bold cyan",
    )
    findings_table.add_column("Severity", min_width=14)
    findings_table.add_column("Category")
    findings_table.add_column("Title", style="bold")
    findings_table.add_column("Description", max_width=60, overflow="ellipsis")
    findings_table.add_column("Fix", max_width=40, overflow="ellipsis")

    # Sort: critical first, then warning, then info
    severity_order = {
        Severity.CRITICAL: 0,
        Severity.WARNING: 1,
        Severity.INFO: 2,
    }
    sorted_findings = sorted(
        report.findings, key=lambda f: severity_order.get(f.severity, 3)
    )

    for finding in sorted_findings:
        fix = finding.fix or ""
        findings_table.add_row(
            _severity_icon(finding.severity),
            finding.category.value,
            finding.title,
            finding.description,
            f"[green]{fix}[/green]" if fix else "",
        )

    console.print(findings_table)
    console.print()


def render_doctor_json(
    report: DoctorReport, console: Console | None = None
) -> None:
    """Render doctor report as JSON."""
    data = report.to_dict()
    output = json.dumps(data, indent=2)
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(output)
