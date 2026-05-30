"""Tech stack detection and compliance analysis for depcheck.

Automatically detects the technology stack of a Python project by analyzing
dependencies, configuration files, and project structure. Checks for
version conflicts, known incompatibilities, license chain compliance,
and provides a comprehensive stack report.
"""

from __future__ import annotations

import enum
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table

from depcheck.pypi import PyPIClient
from depcheck.scanner import (
    discover_dependencies,
    normalize_package_name,
)


class StackCategory(enum.Enum):
    """Category of a technology in the stack."""

    WEB_FRAMEWORK = "web_framework"
    DATABASE = "database"
    ORM = "orm"
    ASYNC = "async"
    HTTP_CLIENT = "http_client"
    CLI = "cli"
    TESTING = "testing"
    LINTING = "linting"
    TYPE_CHECKING = "type_checking"
    CI_CD = "ci_cd"
    CONTAINER = "container"
    CLOUD = "cloud"
    DATA_SCIENCE = "data_science"
    ML_AI = "ml_ai"
    SECURITY = "security"
    LOGGING = "logging"
    SERIALIZATION = "serialization"
    TEMPLATE = "template"
    TASK_QUEUE = "task_queue"
    CACHE = "cache"
    MONITORING = "monitoring"
    CONFIG = "config"
    VALIDATION = "validation"
    DOCUMENTATION = "documentation"
    BUILD = "build"
    PACKAGE_MANAGER = "package_manager"
    UNKNOWN = "unknown"


class ConflictSeverity(enum.Enum):
    """Severity of a detected conflict."""

    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


# Package to stack category mapping
_PACKAGE_CATEGORIES: dict[str, StackCategory] = {
    # Web frameworks
    "django": StackCategory.WEB_FRAMEWORK,
    "flask": StackCategory.WEB_FRAMEWORK,
    "fastapi": StackCategory.WEB_FRAMEWORK,
    "starlette": StackCategory.WEB_FRAMEWORK,
    "tornado": StackCategory.WEB_FRAMEWORK,
    "sanic": StackCategory.WEB_FRAMEWORK,
    "bottle": StackCategory.WEB_FRAMEWORK,
    "pyramid": StackCategory.WEB_FRAMEWORK,
    "falcon": StackCategory.WEB_FRAMEWORK,
    "quart": StackCategory.WEB_FRAMEWORK,
    "litestar": StackCategory.WEB_FRAMEWORK,
    # Database
    "psycopg2": StackCategory.DATABASE,
    "psycopg2-binary": StackCategory.DATABASE,
    "psycopg": StackCategory.DATABASE,
    "pymysql": StackCategory.DATABASE,
    "mysqlclient": StackCategory.DATABASE,
    "asyncpg": StackCategory.DATABASE,
    "aiosqlite": StackCategory.DATABASE,
    "sqlite3": StackCategory.DATABASE,
    "pymongo": StackCategory.DATABASE,
    "motor": StackCategory.DATABASE,
    "cassandra-driver": StackCategory.DATABASE,
    # ORM
    "sqlalchemy": StackCategory.ORM,
    "peewee": StackCategory.ORM,
    "tortoise-orm": StackCategory.ORM,
    "sqlmodel": StackCategory.ORM,
    "pony": StackCategory.ORM,
    # Async
    "asyncio": StackCategory.ASYNC,
    "uvloop": StackCategory.ASYNC,
    "anyio": StackCategory.ASYNC,
    "trio": StackCategory.ASYNC,
    # HTTP clients
    "requests": StackCategory.HTTP_CLIENT,
    "httpx": StackCategory.HTTP_CLIENT,
    "aiohttp": StackCategory.HTTP_CLIENT,
    "urllib3": StackCategory.HTTP_CLIENT,
    "httpcore": StackCategory.HTTP_CLIENT,
    # CLI
    "click": StackCategory.CLI,
    "typer": StackCategory.CLI,
    "argcomplete": StackCategory.CLI,
    "rich": StackCategory.CLI,
    # Testing
    "pytest": StackCategory.TESTING,
    "unittest": StackCategory.TESTING,
    "hypothesis": StackCategory.TESTING,
    "nose2": StackCategory.TESTING,
    "pytest-asyncio": StackCategory.TESTING,
    "pytest-cov": StackCategory.TESTING,
    "pytest-mock": StackCategory.TESTING,
    "freezegun": StackCategory.TESTING,
    "faker": StackCategory.TESTING,
    # Linting
    "ruff": StackCategory.LINTING,
    "flake8": StackCategory.LINTING,
    "pylint": StackCategory.LINTING,
    "black": StackCategory.LINTING,
    "isort": StackCategory.LINTING,
    "pyflakes": StackCategory.LINTING,
    "pycodestyle": StackCategory.LINTING,
    # Type checking
    "mypy": StackCategory.TYPE_CHECKING,
    "pyright": StackCategory.TYPE_CHECKING,
    "pyre-check": StackCategory.TYPE_CHECKING,
    "pytype": StackCategory.TYPE_CHECKING,
    # Cloud / AWS
    "boto3": StackCategory.CLOUD,
    "botocore": StackCategory.CLOUD,
    "google-cloud-storage": StackCategory.CLOUD,
    "azure-storage-blob": StackCategory.CLOUD,
    "gcloud": StackCategory.CLOUD,
    "azure-identity": StackCategory.CLOUD,
    # Data science
    "pandas": StackCategory.DATA_SCIENCE,
    "numpy": StackCategory.DATA_SCIENCE,
    "scipy": StackCategory.DATA_SCIENCE,
    "polars": StackCategory.DATA_SCIENCE,
    "duckdb": StackCategory.DATA_SCIENCE,
    # ML/AI
    "torch": StackCategory.ML_AI,
    "tensorflow": StackCategory.ML_AI,
    "scikit-learn": StackCategory.ML_AI,
    "keras": StackCategory.ML_AI,
    "transformers": StackCategory.ML_AI,
    "onnxruntime": StackCategory.ML_AI,
    "lightgbm": StackCategory.ML_AI,
    "xgboost": StackCategory.ML_AI,
    # Security
    "cryptography": StackCategory.SECURITY,
    "pyjwt": StackCategory.SECURITY,
    "oauthlib": StackCategory.SECURITY,
    "passlib": StackCategory.SECURITY,
    "bcrypt": StackCategory.SECURITY,
    # Logging
    "loguru": StackCategory.LOGGING,
    "structlog": StackCategory.LOGGING,
    "python-json-logger": StackCategory.LOGGING,
    "sentry-sdk": StackCategory.MONITORING,
    # Serialization
    "pydantic": StackCategory.VALIDATION,
    "marshmallow": StackCategory.VALIDATION,
    "attrs": StackCategory.VALIDATION,
    "voluptuous": StackCategory.VALIDATION,
    "cattrs": StackCategory.VALIDATION,
    # Template
    "jinja2": StackCategory.TEMPLATE,
    "mako": StackCategory.TEMPLATE,
    "cheetah3": StackCategory.TEMPLATE,
    # Task queue
    "celery": StackCategory.TASK_QUEUE,
    "huey": StackCategory.TASK_QUEUE,
    "rq": StackCategory.TASK_QUEUE,
    "dramatiq": StackCategory.TASK_QUEUE,
    # Cache
    "redis": StackCategory.CACHE,
    "memcached": StackCategory.CACHE,
    "cachetools": StackCategory.CACHE,
    "diskcache": StackCategory.CACHE,
    # Config
    "python-dotenv": StackCategory.CONFIG,
    "pydantic-settings": StackCategory.CONFIG,
    "dynaconf": StackCategory.CONFIG,
    "hydra-core": StackCategory.CONFIG,
    "configparser": StackCategory.CONFIG,
    # Serialization
    "pyyaml": StackCategory.SERIALIZATION,
    "tomli": StackCategory.SERIALIZATION,
    "toml": StackCategory.SERIALIZATION,
    "msgpack": StackCategory.SERIALIZATION,
    "orjson": StackCategory.SERIALIZATION,
    "ujson": StackCategory.SERIALIZATION,
    # Documentation
    "sphinx": StackCategory.DOCUMENTATION,
    "mkdocs": StackCategory.DOCUMENTATION,
    "pdoc": StackCategory.DOCUMENTATION,
    # Build
    "hatchling": StackCategory.BUILD,
    "setuptools": StackCategory.BUILD,
    "flit-core": StackCategory.BUILD,
    "poetry-core": StackCategory.BUILD,
    "wheel": StackCategory.BUILD,
    "build": StackCategory.BUILD,
}

# Known incompatibility rules between packages/versions
_INCOMPATIBILITY_RULES: list[dict[str, Any]] = [
    {
        "packages": ["django", "flask"],
        "severity": ConflictSeverity.WARNING,
        "message": "Django and Flask are both web frameworks; typically only one is needed.",
    },
    {
        "packages": ["django", "fastapi"],
        "severity": ConflictSeverity.WARNING,
        "message": (
        "Django and FastAPI are both web frameworks; "
        "consider splitting APIs and web app."
    ),
    },
    {
        "packages": ["asyncio", "tornado"],
        "severity": ConflictSeverity.WARNING,
        "message": (
        "Tornado has its own async loop; mixing with asyncio "
        "requires careful handling."
    ),
    },
    {
        "packages": ["celery", "rq"],
        "severity": ConflictSeverity.WARNING,
        "message": "Both Celery and RQ are task queues; standardize on one.",
    },
    {
        "packages": ["pytest", "nose2"],
        "severity": ConflictSeverity.WARNING,
        "message": "Both pytest and nose2 are test runners; pytest is more widely adopted.",
    },
    {
        "packages": ["ruff", "flake8"],
        "severity": ConflictSeverity.WARNING,
        "message": "Ruff can replace flake8; using both is redundant.",
    },
    {
        "packages": ["ruff", "isort"],
        "severity": ConflictSeverity.WARNING,
        "message": "Ruff includes isort functionality; separate isort is redundant.",
    },
    {
        "packages": ["ruff", "black"],
        "severity": ConflictSeverity.WARNING,
        "message": "Ruff includes a formatter (preview); consider if Black is still needed.",
    },
    {
        "packages": ["mypy", "pyright"],
        "severity": ConflictSeverity.WARNING,
        "message": "Both mypy and pyright are type checkers; standardize on one for consistency.",
    },
    {
        "packages": ["pyyaml", "ruamel-yaml"],
        "severity": ConflictSeverity.WARNING,
        "message": "Both are YAML parsers; ruamel.yaml is a superset of PyYAML.",
    },
    {
        "packages": ["requests", "httpx"],
        "severity": ConflictSeverity.WARNING,
        "message": "Both are HTTP clients; httpx supports async and is a near drop-in replacement.",
    },
    {
        "packages": ["pandas", "polars"],
        "severity": ConflictSeverity.WARNING,
        "message": "Both are DataFrame libraries; Polars is faster for most operations.",
    },
    {
        "packages": ["loguru", "structlog"],
        "severity": ConflictSeverity.WARNING,
        "message": "Both are logging enhancement libraries; pick one approach.",
    },
    {
        "packages": ["pydantic", "marshmallow"],
        "severity": ConflictSeverity.WARNING,
        "message": "Both are data validation libraries; consider consolidating.",
    },
]

# Python version compatibility matrix for major frameworks
_PYTHON_COMPAT: dict[str, dict[str, tuple[int, int]]] = {
    "django": {"3.2": (3, 8), "4.0": (3, 8), "4.1": (3, 8), "4.2": (3, 8), "5.0": (3, 10)},
    "flask": {"2.0": (3, 7), "2.1": (3, 7), "2.2": (3, 8), "2.3": (3, 8), "3.0": (3, 8)},
    "fastapi": {
        "0.100": (3, 8), "0.101": (3, 8), "0.102": (3, 8),
        "0.103": (3, 8), "0.104": (3, 8),
    },
    "celery": {"5.2": (3, 7), "5.3": (3, 8), "5.4": (3, 8)},
    "numpy": {"1.24": (3, 8), "1.25": (3, 9), "1.26": (3, 9), "2.0": (3, 9)},
    "pandas": {"1.5": (3, 8), "2.0": (3, 9), "2.1": (3, 9), "2.2": (3, 9)},
}


@dataclass
class StackComponent:
    """A single technology component in the stack."""

    package_name: str
    category: StackCategory
    version: str | None = None
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "category": self.category.value,
            "version": self.version,
            "description": self.description,
        }


@dataclass
class StackConflict:
    """A detected conflict between stack components."""

    packages: list[str]
    severity: ConflictSeverity
    message: str
    category: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "packages": self.packages,
            "severity": self.severity.value,
            "message": self.message,
            "category": self.category,
        }


@dataclass
class PythonCompatEntry:
    """Python version compatibility entry for a package."""

    package_name: str
    version: str | None = None
    min_python: tuple[int, int] | None = None
    current_python: tuple[int, int] | None = None
    is_compatible: bool = True
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "version": self.version,
            "min_python": f"{self.min_python[0]}.{self.min_python[1]}" if self.min_python else None,
            "current_python": f"{self.current_python[0]}.{self.current_python[1]}"
            if self.current_python
            else None,
            "is_compatible": self.is_compatible,
            "note": self.note,
        }


@dataclass
class LicenseChainEntry:
    """License compatibility entry in the dependency chain."""

    package_name: str
    license_id: str
    category: str
    is_compatible: bool = True
    conflict_with: list[str] = field(default_factory=list)
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "license_id": self.license_id,
            "category": self.category,
            "is_compatible": self.is_compatible,
            "conflict_with": self.conflict_with,
            "note": self.note,
        }


@dataclass
class StackResult:
    """Result of tech stack analysis."""

    project_path: str = ""
    components: list[StackComponent] = field(default_factory=list)
    categories: dict[str, list[str]] = field(default_factory=dict)
    conflicts: list[StackConflict] = field(default_factory=list)
    python_compat: list[PythonCompatEntry] = field(default_factory=list)
    license_chain: list[LicenseChainEntry] = field(default_factory=list)
    detected_files: list[str] = field(default_factory=list)
    project_type: str = "unknown"
    python_version: str = ""
    stack_summary: dict[str, int] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "project_type": self.project_type,
            "python_version": self.python_version,
            "components": [c.to_dict() for c in self.components],
            "categories": self.categories,
            "conflicts": [c.to_dict() for c in self.conflicts],
            "python_compat": [p.to_dict() for p in self.python_compat],
            "license_chain": [lic.to_dict() for lic in self.license_chain],
            "detected_files": self.detected_files,
            "stack_summary": self.stack_summary,
            "errors": self.errors,
        }


def _detect_project_type(project_path: Path) -> str:
    """Detect the type of project from its file structure.

    Args:
        project_path: Path to the project directory.

    Returns:
        A string describing the project type.
    """
    indicators: list[str] = []

    if (project_path / "manage.py").exists():
        indicators.append("django")
    if (project_path / "celery.py").exists() or (project_path / "celery_app.py").exists():
        indicators.append("celery")
    if (project_path / "Dockerfile").exists():
        indicators.append("containerized")
    if (project_path / "docker-compose.yml").exists() or (
    (project_path / "docker-compose.yaml").exists()
):
        indicators.append("containerized")
    if (project_path / ".github").is_dir():
        indicators.append("github-ci")
    if (project_path / ".gitlab-ci.yml").exists():
        indicators.append("gitlab-ci")
    if (project_path / "Jenkinsfile").exists():
        indicators.append("jenkins")
    if (project_path / "conftest.py").exists():
        indicators.append("pytest")
    if (project_path / "docs").is_dir():
        indicators.append("documented")

    if not indicators:
        return "python_library"

    return "+".join(indicators)


def _detect_project_files(project_path: Path) -> list[str]:
    """Detect notable project configuration files.

    Args:
        project_path: Path to the project directory.

    Returns:
        List of detected file names.
    """
    notable_files = [
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "requirements.txt",
        "requirements-dev.txt",
        "Pipfile",
        "Pipfile.lock",
        "poetry.lock",
        "Dockerfile",
        "docker-compose.yml",
        "docker-compose.yaml",
        ".pre-commit-config.yaml",
        ".pre-commit-config.yml",
        "Makefile",
        "tox.ini",
        ".readthedocs.yaml",
        ".readthedocs.yml",
        "conftest.py",
        ".env",
        ".env.example",
        "alembic.ini",
        "gunicorn.conf.py",
        "celeryconfig.py",
        "manage.py",
    ]

    found: list[str] = []
    for f in notable_files:
        if (project_path / f).exists():
            found.append(f)
    return found


def _detect_python_version(project_path: Path) -> str:
    """Detect the Python version requirement from project files.

    Args:
        project_path: Path to the project directory.

    Returns:
        Python version string (e.g., '3.11').
    """
    # Check pyproject.toml
    pyproject = project_path / "pyproject.toml"
    if pyproject.exists():
        try:
            content = pyproject.read_text(encoding="utf-8")
            # Look for requires-python
            match = re.search(r'requires-python\s*=\s*["\']>=?(\d+\.\d+)', content)
            if match:
                return match.group(1)
            # Look for python in poetry dependencies
            match = re.search(r'python\s*=\s*["\']>=?(\d+\.\d+)', content)
            if match:
                return match.group(1)
        except (OSError, UnicodeDecodeError):
            pass

    # Check setup.cfg
    setup_cfg = project_path / "setup.cfg"
    if setup_cfg.exists():
        try:
            content = setup_cfg.read_text(encoding="utf-8")
            match = re.search(r'python_requires\s*=\s*>=?(\d+\.\d+)', content)
            if match:
                return match.group(1)
        except (OSError, UnicodeDecodeError):
            pass

    # Fall back to current runtime
    return f"{sys.version_info.major}.{sys.version_info.minor}"


def classify_package(package_name: str) -> StackCategory:
    """Classify a package into a stack category.

    Args:
        package_name: Normalized package name.

    Returns:
        The StackCategory for the package.
    """
    normalized = normalize_package_name(package_name)
    return _PACKAGE_CATEGORIES.get(normalized, StackCategory.UNKNOWN)


def detect_conflicts(package_names: list[str]) -> list[StackConflict]:
    """Detect conflicts between packages in the stack.

    Args:
        package_names: List of normalized package names.

    Returns:
        List of StackConflict instances.
    """
    normalized = {normalize_package_name(n) for n in package_names}
    conflicts: list[StackConflict] = []

    for rule in _INCOMPATIBILITY_RULES:
        rule_packages = [normalize_package_name(p) for p in rule["packages"]]
        if all(p in normalized for p in rule_packages):
            conflicts.append(
                StackConflict(
                    packages=rule["packages"],
                    severity=rule["severity"],
                    message=rule["message"],
                )
            )

    return conflicts


def check_python_compat(
    package_name: str,
    version: str | None,
    current_python: tuple[int, int],
) -> PythonCompatEntry:
    """Check Python version compatibility for a package.

    Args:
        package_name: Package name.
        version: Package version string.
        current_python: Current Python version as (major, minor) tuple.

    Returns:
        PythonCompatEntry with compatibility info.
    """
    entry = PythonCompatEntry(
        package_name=package_name,
        version=version,
        current_python=current_python,
    )

    # Look up in compatibility matrix
    compat_data = _PYTHON_COMPAT.get(package_name)
    if compat_data is None:
        entry.note = "No compatibility data available"
        entry.is_compatible = True
        return entry

    if version is None:
        entry.note = "Version unknown; cannot check compatibility"
        entry.is_compatible = True
        return entry

    # Find best matching version entry
    best_match: tuple[int, int] | None = None
    best_ver_str = ""
    try:
        from packaging.version import Version

        pkg_ver = Version(version)
        for compat_ver_str, min_py in compat_data.items():
            try:
                compat_ver = Version(compat_ver_str)
                if pkg_ver >= compat_ver:
                    if best_match is None or compat_ver > Version(best_ver_str):
                        best_match = min_py
                        best_ver_str = compat_ver_str
            except Exception:
                continue
    except Exception:
        # Fallback: try string prefix matching
        for compat_ver_str, min_py in compat_data.items():
            if version.startswith(compat_ver_str.split(".")[0]):
                best_match = min_py
                best_ver_str = compat_ver_str
                break

    if best_match is not None:
        entry.min_python = best_match
        entry.is_compatible = current_python >= best_match
        if not entry.is_compatible:
            entry.note = (
                f"{package_name} {version} requires Python >={best_match[0]}.{best_match[1]}, "
                f"but current is {current_python[0]}.{current_python[1]}"
            )
        else:
            entry.note = f"Compatible (requires >={best_match[0]}.{best_match[1]})"
    else:
        entry.note = "No matching compatibility entry found"

    return entry


def check_license_chain(
    package_licenses: list[tuple[str, str, str]],  # (name, spdx_id, category)
) -> list[LicenseChainEntry]:
    """Check license compatibility across the dependency chain.

    Detects situations where copyleft licenses may contaminate
    projects that need permissive-only licensing.

    Args:
        package_licenses: List of (package_name, spdx_id, category) tuples.

    Returns:
        List of LicenseChainEntry with compatibility info.
    """
    entries: list[LicenseChainEntry] = []
    copyleft_packages: list[str] = []

    # Identify copyleft packages
    copyleft_ids = {
        "GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later",
        "GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later",
        "AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later",
        "LGPL-2.0", "LGPL-2.1", "LGPL-3.0",
        "MPL-2.0", "MPL-1.1",
        "EUPL-1.2", "CPAL-1.0",
    }

    for name, spdx_id, category in package_licenses:
        is_copyleft = spdx_id in copyleft_ids or category in ("copyleft", "COPYLEFT")
        entry = LicenseChainEntry(
            package_name=name,
            license_id=spdx_id or "UNKNOWN",
            category=category,
            is_compatible=True,
        )

        if is_copyleft:
            copyleft_packages.append(name)
            entry.note = "Copyleft license — may require source distribution"
            entries.append(entry)
        elif not spdx_id or spdx_id == "UNKNOWN":
            entry.note = "License unknown — risk for commercial use"
            entries.append(entry)
        else:
            entries.append(entry)

    # Mark conflicts: if any copyleft package exists, flag it against permissive packages
    if copyleft_packages:
        for entry in entries:
            if not entry.license_id or entry.license_id == "UNKNOWN":
                continue
            if (
    entry.license_id not in copyleft_ids
    and entry.category not in ("copyleft", "COPYLEFT")
):
                entry.conflict_with = copyleft_packages
                entry.note = (
                    f"Permissive license may be incompatible with copyleft: "
                    f"{', '.join(copyleft_packages)}"
                )

    return entries


def run_stack(
    project_path: str | Path,
    check_licenses: bool = False,
) -> StackResult:
    """Run tech stack analysis on a project.

    Args:
        project_path: Path to the project directory.
        check_licenses: Whether to check license chain compatibility.

    Returns:
        StackResult with comprehensive stack analysis.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return StackResult(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    result = StackResult(project_path=str(project_path))

    # Detect project metadata
    result.project_type = _detect_project_type(project_path)
    result.detected_files = _detect_project_files(project_path)
    result.python_version = _detect_python_version(project_path)

    # Parse current Python version
    try:
        py_parts = result.python_version.split(".")
        current_python = (int(py_parts[0]), int(py_parts[1]))
    except (ValueError, IndexError):
        current_python = (sys.version_info.major, sys.version_info.minor)

    # Discover dependencies
    dependencies, _ = discover_dependencies(project_path)

    if not dependencies:
        return StackResult(
            project_path=str(project_path),
            project_type=result.project_type,
            python_version=result.python_version,
            detected_files=result.detected_files,
            errors=["No dependencies found in the project."],
        )

    # Classify each dependency
    categories: dict[str, list[str]] = {}
    for dep in dependencies:
        category = classify_package(dep.name)
        component = StackComponent(
            package_name=dep.name,
            category=category,
            version=dep.version,
        )
        result.components.append(component)

        cat_name = category.value
        if cat_name not in categories:
            categories[cat_name] = []
        categories[cat_name].append(dep.name)

    result.categories = categories

    # Stack summary counts
    for cat_name, pkgs in categories.items():
        result.stack_summary[cat_name] = len(pkgs)

    # Detect conflicts
    pkg_names = [d.name for d in dependencies]
    result.conflicts = detect_conflicts(pkg_names)

    # Check Python version compatibility
    for dep in dependencies:
        compat = check_python_compat(dep.name, dep.version, current_python)
        if not compat.is_compatible or compat.note:
            result.python_compat.append(compat)

    # Check license chain if requested
    if check_licenses:
        license_data: list[tuple[str, str, str]] = []
        with PyPIClient() as pypi_client:
            for dep in dependencies:
                try:
                    info = pypi_client.get_package_info(dep.name)
                    if info:
                        classifiers = info.get("info", {}).get("classifiers", []) or []
                        spdx_id = ""
                        category = "unknown"
                        for c in classifiers:
                            if c.startswith("License :: OSI Approved ::"):
                                spdx_id = c.replace("License :: OSI Approved ::", "").strip()
                                category = "permissive"
                            elif c.startswith("License ::"):
                                parts = c.split("::")
                                if len(parts) >= 2:
                                    spdx_id = parts[-1].strip()
                        license_data.append((dep.name, spdx_id, category))
                    else:
                        license_data.append((dep.name, "UNKNOWN", "unknown"))
                except Exception:
                    license_data.append((dep.name, "UNKNOWN", "unknown"))

        result.license_chain = check_license_chain(license_data)

    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_CATEGORY_DISPLAY_ORDER = [
    StackCategory.WEB_FRAMEWORK,
    StackCategory.DATABASE,
    StackCategory.ORM,
    StackCategory.ASYNC,
    StackCategory.HTTP_CLIENT,
    StackCategory.CLI,
    StackCategory.TESTING,
    StackCategory.LINTING,
    StackCategory.TYPE_CHECKING,
    StackCategory.CLOUD,
    StackCategory.DATA_SCIENCE,
    StackCategory.ML_AI,
    StackCategory.SECURITY,
    StackCategory.LOGGING,
    StackCategory.VALIDATION,
    StackCategory.SERIALIZATION,
    StackCategory.TEMPLATE,
    StackCategory.TASK_QUEUE,
    StackCategory.CACHE,
    StackCategory.CONFIG,
    StackCategory.MONITORING,
    StackCategory.DOCUMENTATION,
    StackCategory.BUILD,
    StackCategory.PACKAGE_MANAGER,
    StackCategory.CONTAINER,
    StackCategory.CI_CD,
    StackCategory.UNKNOWN,
]

_CATEGORY_STYLES: dict[StackCategory, str] = {
    StackCategory.WEB_FRAMEWORK: "bold cyan",
    StackCategory.DATABASE: "bold magenta",
    StackCategory.ORM: "magenta",
    StackCategory.ASYNC: "blue",
    StackCategory.HTTP_CLIENT: "cyan",
    StackCategory.CLI: "green",
    StackCategory.TESTING: "green",
    StackCategory.LINTING: "yellow",
    StackCategory.TYPE_CHECKING: "yellow",
    StackCategory.CLOUD: "blue",
    StackCategory.DATA_SCIENCE: "bold blue",
    StackCategory.ML_AI: "bold red",
    StackCategory.SECURITY: "red",
    StackCategory.LOGGING: "dim",
    StackCategory.VALIDATION: "cyan",
    StackCategory.SERIALIZATION: "white",
    StackCategory.TEMPLATE: "white",
    StackCategory.TASK_QUEUE: "yellow",
    StackCategory.CACHE: "magenta",
    StackCategory.CONFIG: "dim",
    StackCategory.MONITORING: "yellow",
    StackCategory.DOCUMENTATION: "green",
    StackCategory.BUILD: "dim",
    StackCategory.PACKAGE_MANAGER: "dim",
    StackCategory.CONTAINER: "blue",
    StackCategory.CI_CD: "blue",
    StackCategory.UNKNOWN: "dim",
}

_CONFLICT_SEVERITY_STYLES: dict[ConflictSeverity, tuple[str, str]] = {
    ConflictSeverity.WARNING: ("⚠", "yellow"),
    ConflictSeverity.ERROR: ("✗", "red"),
    ConflictSeverity.CRITICAL: ("✗", "red bold"),
}


def render_stack_table(result: StackResult, console: Console | None = None) -> None:
    """Render stack analysis as Rich tables.

    Args:
        result: The stack analysis result.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    console.print()
    console.print(
        f"[bold]depcheck stack[/bold] — Tech Stack Analysis for "
        f"[cyan]{result.project_path}[/cyan]"
    )
    console.print(f" Project type: [bold]{result.project_type}[/bold]")
    console.print(f" Python version: [bold]{result.python_version}[/bold]")

    if result.detected_files:
        console.print(f" Config files: {', '.join(result.detected_files[:10])}")

    console.print()

    # Stack overview
    overview = Table(title="Stack Overview", show_lines=False, pad_edge=False)
    overview.add_column("Category", style="bold")
    overview.add_column("Packages", max_width=60)

    for cat in _CATEGORY_DISPLAY_ORDER:
        if cat.value in result.categories:
            pkgs = result.categories[cat.value]
            style = _CATEGORY_STYLES.get(cat, "white")
            pkg_str = ", ".join(pkgs)
            overview.add_row(f"[{style}]{cat.value}[/{style}]", pkg_str)

    console.print(overview)

    # Conflicts
    if result.conflicts:
        console.print()
        console.print("[bold yellow]⚠ Stack Conflicts[/bold yellow]")

        conflict_table = Table(show_lines=True, pad_edge=False)
        conflict_table.add_column("Severity", justify="center", max_width=10)
        conflict_table.add_column("Packages", style="bold", max_width=30)
        conflict_table.add_column("Message", max_width=60)

        for conflict in result.conflicts:
            icon, color = _CONFLICT_SEVERITY_STYLES.get(conflict.severity, ("?", "white"))
            sev_str = f"[{color}]{icon} {conflict.severity.value}[/{color}]"
            conflict_table.add_row(
                sev_str,
                ", ".join(conflict.packages),
                conflict.message,
            )

        console.print(conflict_table)

    # Python compatibility
    incompat = [p for p in result.python_compat if not p.is_compatible]
    if incompat:
        console.print()
        console.print("[bold red]✗ Python Version Incompatibilities[/bold red]")

        for entry in incompat:
            console.print(f"  [red]•[/red] [bold]{entry.package_name}[/bold] {entry.version or ''}")
            console.print(f"    {entry.note}")

    # License chain
    if result.license_chain:
        copyleft = [lic for lic in result.license_chain if lic.conflict_with]
        if copyleft:
            console.print()
            console.print("[bold yellow]⚠ License Chain Issues[/bold yellow]")
            for entry in copyleft:
                console.print(f"  [bold]{entry.package_name}[/bold] ({entry.license_id})")
                if entry.conflict_with:
                    console.print(f"    {entry.note}")


def render_stack_json(result: StackResult, console: Console | None = None) -> None:
    """Render stack analysis as JSON.

    Args:
        result: The stack analysis result.
        console: Rich console instance.
    """
    if console is None:
        console = Console(force_terminal=False, no_color=True)

    console.print(json.dumps(result.to_dict(), indent=2))
