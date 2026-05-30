"""Dependency explanation engine for depcheck.

Generates human-readable and machine-parseable explanations for why
each dependency exists in a project, what it provides, and its health
status. Designed to be useful for onboarding, auditing, and AI-assisted
code review workflows.

Supports multiple output formats:
  - plain: human-readable paragraphs
  - markdown: structured markdown with headers and tables
  - json: structured JSON for programmatic consumption
  - ai: compact format optimized for LLM context windows
"""

from __future__ import annotations

import enum
import json
import re
import textwrap
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packaging.version import Version

from depcheck.models import HealthStatus, PackageReport, ScanResult
from depcheck.scanner import scan_project


# ---------------------------------------------------------------------------
# Package metadata database (curated knowledge)
# ---------------------------------------------------------------------------

# Well-known packages and their descriptions / categories
# This is intentionally curated rather than API-fetched for reliability
PACKAGE_KNOWLEDGE: dict[str, dict[str, str]] = {
    "requests": {
        "category": "http-client",
        "description": "HTTP library for Python. De facto standard for making HTTP requests with connection pooling, cookies, sessions, and auth.",
        "alternatives": "httpx, aiohttp, urllib3 (lower-level)",
        "ecosystem_role": "Direct HTTP client; many other packages depend on it transitively",
    },
    "urllib3": {
        "category": "http-client",
        "description": "Low-level HTTP connection pool library. Powers the 'requests' library. Use directly only if you need fine-grained connection control.",
        "alternatives": "requests (higher-level), httpx, aiohttp",
        "ecosystem_role": "Transitive dep of requests, pip, and many tools",
    },
    "flask": {
        "category": "web-framework",
        "description": "Lightweight WSGI web framework. Provides routing, templates (Jinja2), and Werkzeug WSGI utilities. Best for small-to-medium APIs and web apps.",
        "alternatives": "fastapi, django, starlette, bottle",
        "ecosystem_role": "Web framework; pulls in Jinja2, Werkzeug, click, itsdangerous",
    },
    "django": {
        "category": "web-framework",
        "description": "Full-featured web framework with ORM, admin, auth, and templating. Best for large applications with complex data models.",
        "alternatives": "flask, fastapi, sqlalchemy+starlette",
        "ecosystem_role": "Full-stack framework; large transitive dependency tree",
    },
    "fastapi": {
        "category": "web-framework",
        "description": "Modern async web framework with automatic OpenAPI docs. Built on Starlette and Pydantic. Best for async APIs with validation.",
        "alternatives": "flask, django, starlette (lower-level)",
        "ecosystem_role": "Async API framework; pulls in starlette, pydantic, uvicorn",
    },
    "numpy": {
        "category": "scientific-computing",
        "description": "Fundamental package for numerical computing in Python. Provides N-dimensional arrays, linear algebra, FFT, and random number capabilities.",
        "alternatives": "jax, cupy (GPU), pytorch (tensors + autograd)",
        "ecosystem_role": "Foundation for scientific Python; transitive dep of pandas, scipy, scikit-learn, matplotlib",
    },
    "pandas": {
        "category": "data-analysis",
        "description": "Data analysis and manipulation library. Provides DataFrames, time series, and statistical operations. Built on NumPy.",
        "alternatives": "polars (faster), dask (distributed), modin (ray-backed)",
        "ecosystem_role": "Data analysis framework; pulls in numpy, python-dateutil, pytz",
    },
    "click": {
        "category": "cli",
        "description": "Command-line interface creation toolkit. Provides decorators for building CLIs with arguments, options, and subcommands.",
        "alternatives": "argparse (stdlib), typer (type-based), docopt",
        "ecosystem_role": "CLI framework; transitive dep of Flask, pip, black, many tools",
    },
    "rich": {
        "category": "cli",
        "description": "Terminal formatting library. Provides colored output, tables, progress bars, markdown rendering, and tree displays.",
        "alternatives": "colorama (basic color), blessed (terminal control), textual (TUI)",
        "ecosystem_role": "Terminal formatting; increasingly common in Python CLI tools",
    },
    "pydantic": {
        "category": "data-validation",
        "description": "Data validation using Python type annotations. Provides BaseModel with automatic validation, serialization, and JSON Schema generation.",
        "alternatives": "marshmallow, attrs+cattrs, dataclasses (stdlib, no validation)",
        "ecosystem_role": "Validation framework; required by FastAPI, used by many APIs",
    },
    "pytest": {
        "category": "testing",
        "description": "Testing framework with fixtures, parametrize, and powerful plugin system. The de facto standard for Python testing.",
        "alternatives": "unittest (stdlib), nose2, hypothesis (property-based)",
        "ecosystem_role": "Test framework; many plugins extend it",
    },
    "httpx": {
        "category": "http-client",
        "description": "Modern HTTP client supporting both sync and async. API-compatible with requests. Best choice for new projects needing async HTTP.",
        "alternatives": "requests (sync only), aiohttp (async), urllib3 (low-level)",
        "ecosystem_role": "HTTP client; supports HTTP/2 via h2 package",
    },
    "jinja2": {
        "category": "templating",
        "description": "Template engine for Python. Provides Django-like template syntax with expressions, inheritance, and filters.",
        "alternatives": "mako, cheetah3, chameleon",
        "ecosystem_role": "Template engine; transitive dep of Flask, Ansible, many tools",
    },
    "setuptools": {
        "category": "packaging",
        "description": "Package build and distribution system. Provides setup.py support, package discovery, and build backend. Increasingly replaced by hatchling/flit.",
        "alternatives": "hatchling, flit, poetry-core, setuptools-rust",
        "ecosystem_role": "Build system; historically ubiquitous, now optional",
    },
    "pip": {
        "category": "packaging",
        "description": "Python package installer. Downloads and installs packages from PyPI and other indexes.",
        "alternatives": "uv, conda, poetry (dependency management)",
        "ecosystem_role": "Package installer; most Python environments include it",
    },
    "wheel": {
        "category": "packaging",
        "description": "Wheel package format support. Provides the bdist_wheel command and wheel installation. Part of the Python packaging ecosystem.",
        "alternatives": "None (standard format)",
        "ecosystem_role": "Packaging format; required for building wheels",
    },
    "certifi": {
        "category": "security",
        "description": "Mozilla CA certificate bundle. Provides SSL/TLS root certificates for HTTPS connections.",
        "alternatives": "pip-system-certs, truststore (Python 3.10+)",
        "ecosystem_role": "SSL certificates; transitive dep of requests, httpx, urllib3",
    },
    "cryptography": {
        "category": "security",
        "description": "Cryptographic primitives and recipes. Provides symmetric/asymmetric encryption, hashing, HMAC, and X.509 operations.",
        "alternatives": "pycryptodome, nacl (libsodium), hashlib (stdlib, limited)",
        "ecosystem_role": "Crypto library; transitive dep of paramiko, pyOpenSSL, jose",
    },
    "packaging": {
        "category": "packaging",
        "description": "Core utilities for Python package versioning, specifiers, and markers. PEP 440 version parsing and comparison.",
        "alternatives": "None (standard library replacement)",
        "ecosystem_role": "Packaging utilities; transitive dep of pip, setuptools, many tools",
    },
    "black": {
        "category": "formatting",
        "description": "Uncompromising code formatter. Enforces a consistent style automatically. The most popular Python code formatter.",
        "alternatives": "ruff (faster, replaces isort too), autopep8, yapf",
        "ecosystem_role": "Code formatter; dev dependency",
    },
    "ruff": {
        "category": "formatting",
        "description": "Fast Python linter and formatter written in Rust. Replaces flake8, isort, and black in many projects.",
        "alternatives": "flake8, black+isort, pylint",
        "ecosystem_role": "Linter/formatter; dev dependency, very fast",
    },
    "mypy": {
        "category": "type-checking",
        "description": "Static type checker for Python. Enforces type annotations and catches type errors at development time.",
        "alternatives": "pyright, pytype, pyre",
        "ecosystem_role": "Type checker; dev dependency",
    },
    "sqlalchemy": {
        "category": "database",
        "description": "SQL toolkit and ORM. Provides both a high-level ORM and a low-level SQL expression language. The standard Python database library.",
        "alternatives": "tortoise-orm (async), peewee, django-orm",
        "ecosystem_role": "Database toolkit; many frameworks integrate with it",
    },
    "alembic": {
        "category": "database",
        "description": "Database migration tool for SQLAlchemy. Provides schema versioning and migration generation.",
        "alternatives": "django-migrations, flyway (JVM), prisma",
        "ecosystem_role": "Migration tool; typically paired with SQLAlchemy",
    },
    "celery": {
        "category": "task-queue",
        "description": "Distributed task queue for Python. Supports Redis, RabbitMQ, and other brokers. Best for background job processing.",
        "alternatives": "huey, dramatiq, arq (async), rq (simpler)",
        "ecosystem_role": "Task queue; pulls in billiard, kombu, vine",
    },
    "redis": {
        "category": "database",
        "description": "Redis Python client. Provides connection pooling, pub/sub, pipelines, and cluster support.",
        "alternatives": "aioredis (now part of redis), valkey client",
        "ecosystem_role": "Cache/message broker client; commonly used with Celery",
    },
    "pillow": {
        "category": "imaging",
        "description": "Python imaging library (PIL fork). Provides image processing, format conversion, and manipulation capabilities.",
        "alternatives": "opencv-python, imageio, wand (ImageMagick)",
        "ecosystem_role": "Image processing; transitive dep of many data/ML tools",
    },
    "matplotlib": {
        "category": "visualization",
        "description": "Comprehensive plotting library. Provides publication-quality figures, charts, and graphs.",
        "alternatives": "plotly (interactive), seaborn (statistical), bokeh (web)",
        "ecosystem_role": "Plotting library; pulls in numpy, python-dateutil, pillow",
    },
    "scipy": {
        "category": "scientific-computing",
        "description": "Scientific computing library. Provides optimization, integration, interpolation, eigenvalue problems, and signal processing.",
        "alternatives": "numpy (simpler), jax (differentiable), numba (JIT)",
        "ecosystem_role": "Scientific computing; built on NumPy",
    },
    "scikit-learn": {
        "category": "machine-learning",
        "description": "Machine learning library. Provides classification, regression, clustering, dimensionality reduction, and model selection.",
        "alternatives": "xgboost, lightgbm, catboost, tensorflow, pytorch",
        "ecosystem_role": "ML toolkit; pulls in numpy, scipy, joblib, threadpoolctl",
    },
    "torch": {
        "category": "machine-learning",
        "description": "Deep learning framework. Provides tensor computation with GPU acceleration and neural network building blocks.",
        "alternatives": "tensorflow, jax, mxnet",
        "ecosystem_role": "Deep learning framework; large dependency tree",
    },
    "tensorflow": {
        "category": "machine-learning",
        "description": "Deep learning framework by Google. Provides Keras high-level API and production deployment tools.",
        "alternatives": "pytorch, jax, paddlepaddle",
        "ecosystem_role": "Deep learning framework; very large dependency tree",
    },
    "starlette": {
        "category": "web-framework",
        "description": "Lightweight ASGI framework. Provides routing, middleware, and WebSocket support. Foundation of FastAPI.",
        "alternatives": "aiohttp, sanic, quart",
        "ecosystem_role": "ASGI framework; transitive dep of FastAPI",
    },
    "uvicorn": {
        "category": "web-server",
        "description": "ASGI web server implementation. Serves ASGI applications (FastAPI, Starlette, etc.) using uvloop.",
        "alternatives": "hypercorn, daphne, gunicorn (WSGI)",
        "ecosystem_role": "ASGI server; typically paired with FastAPI/Starlette",
    },
    "gunicorn": {
        "category": "web-server",
        "description": "WSGI HTTP server. Pre-fork worker model for running Python web apps in production.",
        "alternatives": "uvicorn (ASGI), hypercorn, waitress",
        "ecosystem_role": "WSGI server; typically paired with Flask/Django",
    },
    "werkzeug": {
        "category": "web-framework",
        "description": "WSGI utility library. Provides request/response objects, routing, and development server. Foundation of Flask.",
        "alternatives": "starlette (ASGI), aiohttp (async)",
        "ecosystem_role": "WSGI toolkit; transitive dep of Flask",
    },
    "itsdangerous": {
        "category": "security",
        "description": "Library for signing data. Provides HMAC-based signing for session cookies and other trusted data.",
        "alternatives": "python-jose, pyjwt (tokens)",
        "ecosystem_role": "Data signing; transitive dep of Flask",
    },
    "python-dateutil": {
        "category": "datetime",
        "description": "Extensions to the standard datetime module. Provides flexible date parsing, relative deltas, and recurrence rules.",
        "alternatives": "arrow, pendulum, maya",
        "ecosystem_role": "Date utilities; transitive dep of pandas, matplotlib, boto3",
    },
    "pytz": {
        "category": "datetime",
        "description": "Timezone definitions. Provides the Olson timezone database for Python. Being replaced by zoneinfo (Python 3.9+).",
        "alternatives": "zoneinfo (stdlib 3.9+), pendulum",
        "ecosystem_role": "Timezone data; being superseded by zoneinfo",
    },
    "botocore": {
        "category": "cloud",
        "description": "Low-level AWS SDK interface. Provides service models, request/response handling. Foundation of boto3.",
        "alternatives": "boto3 (higher-level), awscli, moto (mocking)",
        "ecosystem_role": "AWS SDK core; transitive dep of boto3, awscli",
    },
    "boto3": {
        "category": "cloud",
        "description": "AWS SDK for Python. Provides high-level object-oriented API for AWS services (S3, EC2, SQS, etc.).",
        "alternatives": "google-cloud-sdk, azure-sdk, pulumi (IaC)",
        "ecosystem_role": "AWS SDK; pulls in botocore, s3transfer, jmespath",
    },
    "attrs": {
        "category": "data-structures",
        "description": "Classes without boilerplate. Provides decorator-based class creation with validators, converters, and __init__ generation.",
        "alternatives": "dataclasses (stdlib), pydantic (validation), mashumaro (serialization)",
        "ecosystem_role": "Class builder; transitive dep of many libraries",
    },
    "aiohttp": {
        "category": "http-client",
        "description": "Async HTTP client/server framework. Provides both an HTTP client and server with async/await support.",
        "alternatives": "httpx (also async), requests (sync), starlette (server)",
        "ecosystem_role": "Async HTTP; pulls in aiofiles, yarl, multidict",
    },
    "marshmallow": {
        "category": "data-validation",
        "description": "Object serialization/deserialization library. Provides schema-based validation and JSON/ORM conversion.",
        "alternatives": "pydantic, attrs+cattrs, serde",
        "ecosystem_role": "Serialization framework; used by web APIs and ORMs",
    },
    "tenacity": {
        "category": "reliability",
        "description": "Retry library. Provides configurable retry logic with exponential backoff, timeout, and stop conditions.",
        "alternatives": "retry, backoff, stamina",
        "ecosystem_role": "Retry logic; commonly used in API clients and distributed systems",
    },
    "h11": {
        "category": "http-client",
        "description": "Pure-Python HTTP/1.1 protocol library. Used by urllib3, httpx, and other HTTP clients for protocol handling.",
        "alternatives": "h2 (HTTP/2), hyper-h2",
        "ecosystem_role": "HTTP protocol; transitive dep of httpx, urllib3",
    },
    "anyio": {
        "category": "async",
        "description": "Async compatibility layer. Provides async primitives that work with both asyncio and trio.",
        "alternatives": "asyncio (stdlib), trio, curio",
        "ecosystem_role": "Async compatibility; transitive dep of httpx, starlette",
    },
    "sniffio": {
        "category": "async",
        "description": "Library to detect which async library is being used (asyncio, trio, curio).",
        "alternatives": "None (utility)",
        "ecosystem_role": "Async detection; transitive dep of anyio, httpx",
    },
    "idna": {
        "category": "networking",
        "description": "Internationalized domain names support. Implements IDNA 2008 for encoding/decoding international domain names.",
        "alternatives": "None (standard)",
        "ecosystem_role": "IDNA support; transitive dep of requests, httpx, email",
    },
    "charset-normalizer": {
        "category": "encoding",
        "description": "Character set detection library. Replaces chardet for encoding detection in requests and other libraries.",
        "alternatives": "chardet (older, slower), cchardet (faster, C extension)",
        "ecosystem_role": "Encoding detection; transitive dep of requests",
    },
    "tomli": {
        "category": "configuration",
        "description": "TOML parser for Python. Provides a minimal TOML 1.0 parser. Included in stdlib as tomllib since Python 3.11.",
        "alternatives": "tomllib (stdlib 3.11+), toml (older), tomli_w (writer)",
        "ecosystem_role": "TOML parsing; used by many build tools",
    },
    "pluggy": {
        "category": "plugin-system",
        "description": "Plugin management library. Provides the hook specification and implementation system used by pytest.",
        "alternatives": "stevedore, yapsy",
        "ecosystem_role": "Plugin system; transitive dep of pytest",
    },
    "iniconfig": {
        "category": "configuration",
        "description": "INI file parsing library. Lightweight parser for INI-style configuration files.",
        "alternatives": "configparser (stdlib), toml, yaml",
        "ecosystem_role": "INI parsing; transitive dep of pytest",
    },
    "py": {
        "category": "testing",
        "description": "Library with cross-process IPC, path handling, and code assertions. Legacy dependency of pytest (removed in pytest 7+).",
        "alternatives": "pathlib (stdlib), pytest assertions",
        "ecosystem_role": "Legacy testing utility; should not be needed in modern projects",
    },
    "coverage": {
        "category": "testing",
        "description": "Code coverage measurement tool. Measures which lines of code are executed during testing.",
        "alternatives": "pytest-cov (wrapper), hypothesis (property-based)",
        "ecosystem_role": "Coverage measurement; dev dependency",
    },
    "sphinx": {
        "category": "documentation",
        "description": "Documentation generator. Converts reStructuredText into HTML, PDF, and other formats. The standard for Python docs.",
        "alternatives": "mkdocs, jupyter-book, quarto",
        "ecosystem_role": "Documentation; large plugin ecosystem",
    },
    "docutils": {
        "category": "documentation",
        "description": "reStructuredText parsing and conversion library. Foundation of Sphinx.",
        "alternatives": "markdown, commonmark",
        "ecosystem_role": "RST processing; transitive dep of Sphinx",
    },
    "paramiko": {
        "category": "networking",
        "description": "SSH2 protocol library. Provides SSH client and server functionality. Used by Fabric for remote execution.",
        "alternatives": "asyncssh (async), pexpect (terminal), fabric (higher-level)",
        "ecosystem_role": "SSH library; pulls in cryptography, bcrypt, pynacl",
    },
    "yaml": {
        "category": "configuration",
        "description": "YAML parser and emitter. The standard Python YAML library (PyYAML).",
        "alternatives": "ruamel.yaml (round-trip), strictyaml (safer), omegaconf",
        "ecosystem_role": "YAML parsing; used by many config-driven tools",
    },
    "pyyaml": {
        "category": "configuration",
        "description": "YAML parser and emitter. The standard Python YAML library.",
        "alternatives": "ruamel.yaml, strictyaml, omegaconf",
        "ecosystem_role": "YAML parsing; widely used in DevOps and config tools",
    },
}


def get_package_info(name: str) -> dict[str, str]:
    """Get known information about a package.

    Falls back to a generic description based on the package name
    if no curated entry exists.
    """
    normalized = name.lower().replace("-", "_").replace(".", "_")

    # Try direct lookup, then normalized
    if name.lower() in PACKAGE_KNOWLEDGE:
        return PACKAGE_KNOWLEDGE[name.lower()]
    if normalized in PACKAGE_KNOWLEDGE:
        return PACKAGE_KNOWLEDGE[normalized]

    # Try with hyphens/underscores swapped
    alt = name.lower().replace("-", "_")
    if alt in PACKAGE_KNOWLEDGE:
        return PACKAGE_KNOWLEDGE[alt]
    alt = name.lower().replace("_", "-")
    if alt in PACKAGE_KNOWLEDGE:
        return PACKAGE_KNOWLEDGE[alt]

    return {
        "category": "unknown",
        "description": f"Python package '{name}'. No curated description available.",
        "alternatives": "Unknown",
        "ecosystem_role": "Unknown",
    }


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class OutputFormat(enum.Enum):
    """Output format for dependency explanations."""

    PLAIN = "plain"
    MARKDOWN = "markdown"
    JSON = "json"
    AI = "ai"


@dataclass
class PackageExplanation:
    """Full explanation for a single package."""

    name: str
    installed_version: str
    latest_version: str | None = None
    status: HealthStatus = HealthStatus.UNKNOWN
    category: str = "unknown"
    description: str = ""
    ecosystem_role: str = ""
    alternatives: str = ""
    is_outdated: bool = False
    is_vulnerable: bool = False
    is_unmaintained: bool = False
    has_license_issue: bool = False
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    license_info: dict[str, Any] | None = None
    risk_summary: str = ""
    action_items: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "installed_version": self.installed_version,
            "latest_version": self.latest_version,
            "status": self.status.value,
            "category": self.category,
            "description": self.description,
            "ecosystem_role": self.ecosystem_role,
            "alternatives": self.alternatives,
            "is_outdated": self.is_outdated,
            "is_vulnerable": self.is_vulnerable,
            "is_unmaintained": self.is_unmaintained,
            "has_license_issue": self.has_license_issue,
            "vulnerabilities": self.vulnerabilities,
            "license_info": self.license_info,
            "risk_summary": self.risk_summary,
            "action_items": self.action_items,
        }


@dataclass
class ExplainReport:
    """Complete explanation report for a project's dependencies."""

    project_path: str
    packages: list[PackageExplanation] = field(default_factory=list)
    total_packages: int = 0
    at_risk_count: int = 0
    healthy_count: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "total_packages": self.total_packages,
            "at_risk_count": self.at_risk_count,
            "healthy_count": self.healthy_count,
            "packages": [p.to_dict() for p in self.packages],
            "timestamp": self.timestamp,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Explanation generation
# ---------------------------------------------------------------------------


def _generate_risk_summary(pkg: PackageReport) -> str:
    """Generate a human-readable risk summary for a package."""
    risks: list[str] = []

    if pkg.is_vulnerable:
        sev_counts: dict[str, int] = {}
        for v in pkg.vulnerabilities:
            sev = v.severity.lower() if v.severity else "unknown"
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        parts = [f"{count} {sev}" for sev, count in sorted(sev_counts.items())]
        risks.append(f"Has known vulnerabilities ({', '.join(parts)})")

    if pkg.is_outdated:
        if pkg.latest_version:
            try:
                inst = Version(pkg.installed_version)
                lat = Version(pkg.latest_version)
                if inst.major < lat.major:
                    risks.append(f"Major version behind (latest: {pkg.latest_version})")
                elif inst.minor < lat.minor:
                    risks.append(f"Minor version behind (latest: {pkg.latest_version})")
                else:
                    risks.append(f"Patch version behind (latest: {pkg.latest_version})")
            except Exception:
                risks.append(f"Outdated (latest: {pkg.latest_version})")

    if pkg.is_unmaintained:
        risks.append("Package appears unmaintained (no recent releases)")

    if pkg.is_yanked:
        risks.append("Installed version has been yanked from PyPI")

    if pkg.is_removed:
        risks.append("Package has been removed from PyPI")

    if pkg.has_license_issue:
        risks.append("License compliance issue detected")

    return "; ".join(risks) if risks else "No known risks"


def _generate_action_items(pkg: PackageReport) -> list[str]:
    """Generate actionable recommendations for a package."""
    actions: list[str] = []

    if pkg.is_vulnerable:
        actions.append(f"Upgrade {pkg.name} to fix known vulnerabilities")
        if pkg.latest_version:
            actions.append(f"  → pip install {pkg.name}=={pkg.latest_version}")

    if pkg.is_outdated and not pkg.is_vulnerable:
        if pkg.latest_version:
            actions.append(f"Consider upgrading: pip install {pkg.name}=={pkg.latest_version}")

    if pkg.is_unmaintained:
        info = get_package_info(pkg.name)
        if info.get("alternatives") and info["alternatives"] != "Unknown":
            actions.append(
                f"Package may be unmaintained — consider alternatives: {info['alternatives']}"
            )
        else:
            actions.append("Package may be unmaintained — audit for continued suitability")

    if pkg.is_yanked:
        actions.append(f"Version {pkg.installed_version} was yanked — upgrade immediately")

    if pkg.is_removed:
        actions.append("Package removed from PyPI — find an alternative or vendor it")

    if pkg.has_license_issue:
        if pkg.license_info:
            actions.append(
                f"Review license: {pkg.license_info.raw_license or pkg.license_info.spdx_id}"
            )
            if pkg.license_info.compliance_note:
                actions.append(f"  Note: {pkg.license_info.compliance_note}")

    return actions


def explain_package(pkg: PackageReport) -> PackageExplanation:
    """Generate a full explanation for a single package."""
    info = get_package_info(pkg.name)

    return PackageExplanation(
        name=pkg.name,
        installed_version=pkg.installed_version,
        latest_version=pkg.latest_version,
        status=pkg.status,
        category=info.get("category", "unknown"),
        description=info.get("description", ""),
        ecosystem_role=info.get("ecosystem_role", ""),
        alternatives=info.get("alternatives", ""),
        is_outdated=pkg.is_outdated,
        is_vulnerable=pkg.is_vulnerable,
        is_unmaintained=pkg.is_unmaintained,
        has_license_issue=pkg.has_license_issue,
        vulnerabilities=[v.to_dict() for v in pkg.vulnerabilities],
        license_info=pkg.license_info.to_dict() if pkg.license_info else None,
        risk_summary=_generate_risk_summary(pkg),
        action_items=_generate_action_items(pkg),
    )


def explain_project(
    project_path: str = ".",
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
) -> ExplainReport:
    """Generate explanations for all dependencies in a project.

    This is the main entry point for the `depcheck explain` command.
    """
    project = Path(project_path).resolve()

    scan_result = scan_project(
        project_path=str(project),
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
    )

    explanations: list[PackageExplanation] = []
    for pkg in scan_result.packages:
        explanations.append(explain_package(pkg))

    at_risk = sum(
        1
        for e in explanations
        if e.is_vulnerable or e.is_unmaintained or e.is_outdated
    )
    healthy = len(explanations) - at_risk

    return ExplainReport(
        project_path=str(project),
        packages=explanations,
        total_packages=len(explanations),
        at_risk_count=at_risk,
        healthy_count=healthy,
        errors=scan_result.errors,
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def render_explain_plain(report: ExplainReport, *, console: Any = None) -> None:
    """Render dependency explanations as plain text."""
    from rich.console import Console

    if console is None:
        console = Console()

    console.print(f"\n[bold]Dependency Report: {report.project_path}[/bold]")
    console.print(
        f"  {report.total_packages} packages | "
        f"{report.healthy_count} healthy | "
        f"{report.at_risk_count} at risk\n"
    )

    for pkg in report.packages:
        status_icons = {
            HealthStatus.HEALTHY: "✓",
            HealthStatus.OUTDATED: "↑",
            HealthStatus.VULNERABLE: "!",
            HealthStatus.UNMAINTAINED: "⚠",
            HealthStatus.YANKED: "✗",
            HealthStatus.REMOVED: "✗",
            HealthStatus.UNKNOWN: "?",
        }
        icon = status_icons.get(pkg.status, "?")
        color = {
            HealthStatus.HEALTHY: "green",
            HealthStatus.OUTDATED: "yellow",
            HealthStatus.VULNERABLE: "red",
            HealthStatus.UNMAINTAINED: "yellow",
            HealthStatus.YANKED: "red",
            HealthStatus.REMOVED: "red",
            HealthStatus.UNKNOWN: "dim",
        }.get(pkg.status, "dim")

        console.print(f"[{color}]{icon}[/{color}] [bold]{pkg.name}[/bold] {pkg.installed_version}", highlight=False)

        if pkg.description:
            wrapped = textwrap.fill(pkg.description, width=72, initial_indent="  ", subsequent_indent="  ")
            console.print(f"  [dim]{wrapped}[/dim]")

        if pkg.category != "unknown":
            console.print(f"  Category: {pkg.category}")

        if pkg.ecosystem_role:
            console.print(f"  Role: {pkg.ecosystem_role}")

        if pkg.risk_summary and pkg.risk_summary != "No known risks":
            console.print(f"  [yellow]Risk: {pkg.risk_summary}[/yellow]")

        if pkg.action_items:
            for action in pkg.action_items:
                if action.startswith("  "):
                    console.print(f"  [dim]{action}[/dim]")
                else:
                    console.print(f"  → {action}")

        if pkg.alternatives and pkg.alternatives != "Unknown":
            console.print(f"  [dim]Alternatives: {pkg.alternatives}[/dim]")

        console.print()


def render_explain_markdown(report: ExplainReport, *, console: Any = None) -> None:
    """Render dependency explanations as Markdown."""
    from rich.console import Console
    from rich.markdown import Markdown

    if console is None:
        console = Console()

    lines: list[str] = []
    lines.append(f"# Dependency Report: {report.project_path}")
    lines.append("")
    lines.append(
        f"**{report.total_packages} packages** | "
        f"✅ {report.healthy_count} healthy | "
        f"⚠️ {report.at_risk_count} at risk"
    )
    lines.append("")

    # Group by category
    categories: dict[str, list[PackageExplanation]] = {}
    for pkg in report.packages:
        cat = pkg.category or "unknown"
        categories.setdefault(cat, []).append(pkg)

    for cat in sorted(categories.keys()):
        cat_title = cat.replace("-", " ").replace("_", " ").title()
        lines.append(f"## {cat_title}")
        lines.append("")

        lines.append("| Package | Version | Status | Risk | Alternatives |")
        lines.append("|---------|---------|--------|------|-------------|")

        for pkg in categories[cat]:
            status_str = pkg.status.value
            risk_str = pkg.risk_summary if pkg.risk_summary != "No known risks" else "—"
            alt_str = pkg.alternatives if pkg.alternatives != "Unknown" else "—"
            # Escape pipe characters in table
            risk_str = risk_str.replace("|", "\\|")
            alt_str = alt_str.replace("|", "\\|")
            lines.append(
                f"| **{pkg.name}** | {pkg.installed_version} | {status_str} "
                f"| {risk_str} | {alt_str} |"
            )

        lines.append("")

    # Action items section
    all_actions: list[tuple[str, list[str]]] = []
    for pkg in report.packages:
        if pkg.action_items:
            all_actions.append((pkg.name, pkg.action_items))

    if all_actions:
        lines.append("## Action Items")
        lines.append("")
        for name, actions in all_actions:
            lines.append(f"### {name}")
            for action in actions:
                if action.startswith("  "):
                    lines.append(f"  `{action.strip()}`")
                else:
                    lines.append(f"- {action}")
            lines.append("")

    md_text = "\n".join(lines)
    console.print(Markdown(md_text))


def render_explain_json(report: ExplainReport, *, console: Any = None) -> None:
    """Render dependency explanations as JSON."""
    from rich.console import Console

    if console is None:
        console = Console(force_terminal=False, no_color=True)

    console.print(json.dumps(report.to_dict(), indent=2))


def render_explain_ai(report: ExplainReport, *, console: Any = None) -> None:
    """Render dependency explanations in AI-optimized compact format.

    Designed for inclusion in LLM context windows. Uses a compact
    key=value format that's both human and machine readable.
    """
    from rich.console import Console

    if console is None:
        console = Console(force_terminal=False, no_color=True)

    lines: list[str] = []
    lines.append(f"DEPS {report.project_path} total={report.total_packages} risk={report.at_risk_count} ok={report.healthy_count}")

    for pkg in report.packages:
        parts = [
            f"PKG {pkg.name}",
            f"ver={pkg.installed_version}",
        ]
        if pkg.latest_version:
            parts.append(f"latest={pkg.latest_version}")
        parts.append(f"status={pkg.status.value}")
        parts.append(f"cat={pkg.category}")

        if pkg.is_vulnerable:
            parts.append("VULN")
        if pkg.is_outdated:
            parts.append("OUTDATED")
        if pkg.is_unmaintained:
            parts.append("UNMAINTAINED")
        if pkg.has_license_issue:
            parts.append("LICENSE_ISSUE")

        if pkg.description:
            # Truncate for compactness
            desc = pkg.description[:100]
            if len(pkg.description) > 100:
                desc += "..."
            parts.append(f'desc="{desc}"')

        if pkg.action_items:
            actions_str = " | ".join(pkg.action_items[:3])
            parts.append(f'actions="{actions_str}"')

        lines.append(" ".join(parts))

    console.print("\n".join(lines))
