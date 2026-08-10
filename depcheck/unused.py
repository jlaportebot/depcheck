"""Unused dependency detection for depcheck.

Detects dependencies that are declared in requirements.txt / pyproject.toml /
Pipfile but never imported anywhere in the project's source code. Uses AST-based
parsing for accuracy (not fragile regex), maintains a comprehensive mapping of
import names to distribution package names, and assigns a confidence score to
each finding to reduce false positives.

The analyzer also detects the inverse problem — packages imported in source code
but missing from the manifest — when run with ``--include-undeclared``.

Features:
    - AST-based import extraction (handles ``import X``, ``from X import Y``,
      nested imports inside functions, relative imports, and try/except fallbacks)
    - Comprehensive import-name -> distribution-name mapping for ~150 packages
      where the import name differs from the PyPI distribution name
    - Confidence scoring (HIGH / MEDIUM / LOW) based on heuristics
    - Exclude patterns for vendored / generated / test directories
    - JSON and Rich table output formats
    - CI-friendly exit codes via ``--fail-on``
"""

from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import ParsedDependency
from depcheck.scanner import discover_dependencies, normalize_package_name

# ---------------------------------------------------------------------------
# Stdlib module registry
# ---------------------------------------------------------------------------

# Python 3.10+ exposes ``sys.stdlib_module_names`` as a frozenset of all stdlib
# module names. We use that when available and fall back to a curated set for 3.9.
_STDLIB_FALLBACK: frozenset[str] = frozenset(
    {
        "abc",
        "aifc",
        "argparse",
        "array",
        "ast",
        "asynchat",
        "asyncio",
        "asyncore",
        "atexit",
        "audioop",
        "base64",
        "bdb",
        "binascii",
        "binhex",
        "bisect",
        "builtins",
        "bz2",
        "calendar",
        "cgi",
        "cgitb",
        "chunk",
        "cmath",
        "cmd",
        "code",
        "codecs",
        "codeop",
        "collections",
        "colorsys",
        "compileall",
        "concurrent",
        "configparser",
        "contextlib",
        "contextvars",
        "copy",
        "copyreg",
        "cProfile",
        "crypt",
        "csv",
        "ctypes",
        "curses",
        "dataclasses",
        "datetime",
        "dbm",
        "decimal",
        "difflib",
        "dis",
        "distutils",
        "doctest",
        "email",
        "encodings",
        "ensurepip",
        "enum",
        "errno",
        "faulthandler",
        "fcntl",
        "filecmp",
        "fileinput",
        "fnmatch",
        "fractions",
        "ftplib",
        "functools",
        "gc",
        "genericpath",
        "getopt",
        "getpass",
        "gettext",
        "glob",
        "graphlib",
        "gzip",
        "hashlib",
        "heapq",
        "hmac",
        "html",
        "http",
        "idlelib",
        "imaplib",
        "imghdr",
        "imp",
        "importlib",
        "inspect",
        "io",
        "ipaddress",
        "itertools",
        "json",
        "keyword",
        "lib2to3",
        "linecache",
        "locale",
        "logging",
        "lzma",
        "mailbox",
        "mailcap",
        "marshal",
        "math",
        "mimetypes",
        "mmap",
        "modulefinder",
        "multiprocessing",
        "netrc",
        "nis",
        "nntplib",
        "numbers",
        "opcode",
        "operator",
        "optparse",
        "os",
        "ossaudiodev",
        "pathlib",
        "pdb",
        "pickle",
        "pickletools",
        "pipes",
        "pkgutil",
        "platform",
        "plistlib",
        "poplib",
        "posix",
        "posixpath",
        "pprint",
        "profile",
        "pstats",
        "pty",
        "pwd",
        "py_compile",
        "pyclbr",
        "pydoc",
        "pydoc_data",
        "pytz",
        "queue",
        "quopri",
        "random",
        "re",
        "readline",
        "reprlib",
        "resource",
        "rlcompleter",
        "runpy",
        "sched",
        "secrets",
        "select",
        "selectors",
        "shelve",
        "shlex",
        "shutil",
        "signal",
        "site",
        "smtpd",
        "smtplib",
        "sndhdr",
        "socket",
        "socketserver",
        "spwd",
        "sqlite3",
        "sre_compile",
        "sre_constants",
        "sre_parse",
        "ssl",
        "stat",
        "statistics",
        "string",
        "stringprep",
        "struct",
        "subprocess",
        "sunau",
        "symtable",
        "sys",
        "sysconfig",
        "syslog",
        "tabnanny",
        "tarfile",
        "telnetlib",
        "tempfile",
        "termios",
        "test",
        "textwrap",
        "threading",
        "time",
        "timeit",
        "tkinter",
        "token",
        "tokenize",
        "tomllib",
        "trace",
        "traceback",
        "tracemalloc",
        "tty",
        "turtle",
        "turtledemo",
        "types",
        "typing",
        "unicodedata",
        "unittest",
        "urllib",
        "uu",
        "uuid",
        "venv",
        "warnings",
        "wave",
        "weakref",
        "webbrowser",
        "winreg",
        "winsound",
        "wsgiref",
        "xdrlib",
        "xml",
        "xmlrpc",
        "zipapp",
        "zipfile",
        "zipimport",
        "zlib",
        "zoneinfo",
        "_thread",
        "builtins",
    }
)


def get_stdlib_modules() -> frozenset[str]:
    """Return the set of standard-library module names.

    Uses :data:`sys.stdlib_module_names` on Python 3.10+ for completeness and
    falls back to a curated set on 3.9.

    Returns:
        Frozen set of stdlib module names (lower-cased).
    """
    names = getattr(sys, "stdlib_module_names", None)
    if names is not None:
        return frozenset(names)
    return _STDLIB_FALLBACK


# ---------------------------------------------------------------------------
# Import-name -> distribution-name mapping
# ---------------------------------------------------------------------------

# When a package's import name differs from its PyPI distribution name, we need
# to map the import back to the declared dependency.  This is a curated list of
# the most common mismatches.  Keys are the *import* name (as written in code),
# values are the *distribution* name as it appears in requirements.txt/pyproject.
IMPORT_TO_PACKAGE: dict[str, str] = {
    # --- Imaging / CV ---
    "cv2": "opencv-python",
    "PIL": "pillow",
    "skimage": "scikit-image",
    "sklearn": "scikit-learn",
    # --- Data / science ---
    "numpy": "numpy",
    "pandas": "pandas",
    "scipy": "scipy",
    "matplotlib": "matplotlib",
    "mpl_toolkits": "matplotlib",
    "seaborn": "seaborn",
    "bokeh": "bokeh",
    "plotly": "plotly",
    "altair": "altair",
    "h5py": "h5py",
    "tables": "pytables",
    "xarray": "xarray",
    "dask": "dask",
    "polars": "polars",
    "sympy": "sympy",
    # --- ML / deep learning ---
    "torch": "torch",
    "torchvision": "torchvision",
    "torchaudio": "torchaudio",
    "tensorflow": "tensorflow",
    "keras": "keras",
    "transformers": "transformers",
    "datasets": "datasets",
    "tokenizers": "tokenizers",
    "accelerate": "accelerate",
    "peft": "peft",
    "trl": "trl",
    "xgboost": "xgboost",
    "lightgbm": "lightgbm",
    "catboost": "catboost",
    # --- Web frameworks ---
    "django": "django",
    "flask": "flask",
    "fastapi": "fastapi",
    "starlette": "starlette",
    "sanic": "sanic",
    "tornado": "tornado",
    "bottle": "bottle",
    "aiohttp": "aiohttp",
    # --- Web / HTTP ---
    "requests": "requests",
    "httpx": "httpx",
    "urllib3": "urllib3",
    "httpcore": "httpcore",
    "h11": "h11",
    "h2": "h2",
    "websocket": "websocket-client",
    "websockets": "websockets",
    # --- CLI ---
    "click": "click",
    "typer": "typer",
    "rich": "rich",
    "textual": "textual",
    "prompt_toolkit": "prompt-toolkit",
    "argcomplete": "argcomplete",
    # --- YAML / TOML / serialization ---
    "yaml": "pyyaml",
    "tomli": "tomli",
    "tomllib": "tomli",  # backport on <3.11
    "tomli_w": "tomli-w",
    "msgpack": "msgpack",
    "orjson": "orjson",
    "ujson": "ujson",
    "cjson": "python-cjson",
    # --- Serialization / data ---
    "marshmallow": "marshmallow",
    "attrs": "attrs",
    "cattrs": "cattrs",
    "pydantic": "pydantic",
    "dataclass_utils": "dataclass-utils",
    # --- Database / ORM ---
    "sqlalchemy": "sqlalchemy",
    "alembic": "alembic",
    "tortoise": "tortoise-orm",
    "ormar": "ormar",
    "peewee": "peewee",
    "pymongo": "pymongo",
    "redis": "redis",
    "aioredis": "aioredis",
    "psycopg2": "psycopg2-binary",
    "asyncpg": "asyncpg",
    "sqlmodel": "sqlmodel",
    # --- Date / time ---
    "dateutil": "python-dateutil",
    "pendulum": "pendulum",
    "arrow": "arrow",
    "may": "maya",
    "pytz": "pytz",
    # --- Crypto ---
    "Crypto": "pycryptodome",
    "nacl": "pynacl",
    "OpenSSL": "pyopenssl",
    "cryptography": "cryptography",
    "jwt": "pyjwt",
    # --- File formats / parsing ---
    "openpyxl": "openpyxl",
    "xlrd": "xlrd",
    "xlwt": "xlwt",
    "lxml": "lxml",
    "bs4": "beautifulsoup4",
    "soupsieve": "soupsieve",
    "feedparser": "feedparser",
    "markdown": "markdown",
    # --- Misc ecosystem ---
    "git": "gitpython",
    "serial": "pyserial",
    "usb": "pyusb",
    "wx": "wxpython",
    "gi": "pygobject",
    "magic": "python-magic",
    "Bio": "biopython",
    "tifffile": "tifffile",
    "wtforms": "wtforms",
    "flask_wtf": "flask-wtf",
    "werkzeug": "werkzeug",
    "jinja2": "jinja2",
    "mako": "mako",
    "bleach": "bleach",
    # --- Testing / lint ---
    "pytest": "pytest",
    "hypothesis": "hypothesis",
    "mock": "mock",
    "vcr": "vcrpy",
    "responses": "responses",
    "freezegun": "freezegun",
    "factory": "factory_boy",
    "faker": "faker",
    # --- Logging / observability ---
    "structlog": "structlog",
    "loguru": "loguru",
    "sentry_sdk": "sentry-sdk",
    "opentelemetry": "opentelemetry-sdk",
    # --- Async / concurrency ---
    "anyio": "anyio",
    "trio": "trio",
    "greenlet": "greenlet",
    "gevent": "gevent",
    "eventlet": "eventlet",
    # --- Packaging / build ---
    "setuptools": "setuptools",
    "pip": "pip",
    "wheel": "wheel",
    "build": "build",
    "hatchling": "hatchling",
    "flit_core": "flit-core",
    "poetry": "poetry",
    # --- Misc ---
    "dotenv": "python-dotenv",
    "colorama": "colorama",
    "tqdm": "tqdm",
    "tenacity": "tenacity",
    "boltons": "boltons",
    "toolz": "toolz",
    "cytoolz": "cytoolz",
    "more_itertools": "more-itertools",
    "deepdiff": "deepdiff",
    "pythonjsonlogger": "python-json-logger",
    "backoff": "backoff",
    "croniter": "croniter",
    "apscheduler": "apscheduler",
    "celery": "celery",
    "rq": "rq",
    "dramatiq": "dramatiq",
    "kombu": "kombu",
    "boto3": "boto3",
    "botocore": "botocore",
    "aiobotocore": "aiobotocore",
    "google": "google-cloud-storage",  # best-effort
    "googleapiclient": "google-api-python-client",
    "anthropic": "anthropic",
    "openai": "openai",
    "google.generativeai": "google-generativeai",
    "pinecone": "pinecone-client",
    "chromadb": "chromadb",
    "langchain": "langchain",
    "langsmith": "langsmith",
    "qdrant": "qdrant-client",
    # --- Common single-name mismatches ---
    "attr": "attrs",
    "_thread": "_thread",
}


def resolve_import_to_package(import_name: str) -> str | None:
    """Resolve a top-level import name to its PyPI distribution name.

    The mapping handles packages where the import name differs from the
    distribution name (e.g. ``import yaml`` -> ``pyyaml``). For packages
    whose import name matches the distribution name, the normalized form
    is returned unchanged.

    Args:
        import_name: The top-level module name as written in code
            (e.g. ``"PIL"``, ``"yaml"``, ``"requests"``).

    Returns:
        The distribution name if resolvable, otherwise the normalized
        import name (best-effort match).  Returns ``None`` only if the
        import name is empty.
    """
    if not import_name:
        return None
    # Top-level component (drop sub-module qualifiers like ``google.cloud.storage``)
    top = import_name.split(".")[0]
    mapped = IMPORT_TO_PACKAGE.get(top) or IMPORT_TO_PACKAGE.get(import_name)
    if mapped:
        return normalize_package_name(mapped)
    return normalize_package_name(top)


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


class Confidence(StrEnum):
    """Confidence level that a declared dependency is truly unused."""

    HIGH = "high"  # No import found anywhere, package not a workspace dep
    MEDIUM = "medium"  # No import found, but may be a transitive-only dep
    LOW = "low"  # No import found, but package commonly used indirectly


@dataclass
class UnusedFinding:
    """Single finding for a declared-but-unused dependency.

    Attributes:
        name: Normalized distribution name.
        declared_version: Version as declared in manifest (may be ``None``).
        declared_in: Files where the dependency was declared.
        confidence: HIGH / MEDIUM / LOW.
        reason: Human-readable explanation of the confidence level.
        imported_indirectly: True if the package is a transitive dependency
            of another declared package (best-effort heuristic).
    """

    name: str
    declared_version: str | None = None
    declared_in: list[str] = field(default_factory=list)
    confidence: Confidence = Confidence.HIGH
    reason: str = ""
    imported_indirectly: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict for JSON output."""
        return {
            "name": self.name,
            "declared_version": self.declared_version,
            "declared_in": self.declared_in,
            "confidence": self.confidence.value,
            "reason": self.reason,
            "imported_indirectly": self.imported_indirectly,
        }


@dataclass
class UndeclaredFinding:
    """A package imported in source code but missing from the manifest.

    Attributes:
        import_name: Top-level import name as found in source.
        resolved_package: Best-effort distribution name (may equal import_name).
        used_in: List of files where the import was found.
    """

    import_name: str
    resolved_package: str
    used_in: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "import_name": self.import_name,
            "resolved_package": self.resolved_package,
            "used_in": self.used_in,
        }


@dataclass
class UnusedResult:
    """Full result of an unused-dependency analysis.

    Attributes:
        project_path: Absolute path of the analyzed project.
        declared: Total number of declared dependencies.
        imported: Set of distribution names detected as imported.
        unused: List of UnusedFinding for declared-but-unused packages.
        undeclared: List of UndeclaredFinding for imported-but-not-declared.
        files_scanned: Number of Python source files scanned.
        manifest_files: List of manifest files parsed.
        errors: Non-fatal warnings encountered during analysis.
    """

    project_path: str = ""
    declared: int = 0
    imported: list[str] = field(default_factory=list)
    unused: list[UnusedFinding] = field(default_factory=list)
    undeclared: list[UndeclaredFinding] = field(default_factory=list)
    files_scanned: int = 0
    manifest_files: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "files_scanned": self.files_scanned,
            "manifest_files": self.manifest_files,
            "declared_count": self.declared,
            "imported_count": len(self.imported),
            "unused": [f.to_dict() for f in self.unused],
            "undeclared": [f.to_dict() for f in self.undeclared],
            "errors": self.errors,
        }


@dataclass
class UnusedConfig:
    """Configuration for the unused-dependency analyzer.

    Attributes:
        exclude_dirs: Directory names to skip during source scanning
            (e.g. ``{"tests", "venv"}``).
        exclude_patterns: Glob patterns to exclude (matched against full path).
        include_undeclared: Also report imported-but-not-declared packages.
        include_transitive: Consider a package "used" if another declared
            package depends on it (best-effort; requires network).
        confidence_threshold: Minimum confidence level to report.
        max_files: Maximum number of Python files to scan (safety valve).
    """

    exclude_dirs: set[str] = field(
        default_factory=lambda: {
            ".venv",
            "venv",
            "env",
            ".git",
            "__pycache__",
            "node_modules",
            ".tox",
            ".mypy_cache",
            ".pytest_cache",
            ".ruff_cache",
            "dist",
            "build",
            "egg-info",
            ".eggs",
        }
    )
    exclude_patterns: list[str] = field(default_factory=list)
    include_undeclared: bool = False
    include_transitive: bool = False
    confidence_threshold: Confidence = Confidence.LOW
    max_files: int = 2000


# ---------------------------------------------------------------------------
# Import scanner (AST-based)
# ---------------------------------------------------------------------------


class ImportScanner:
    """Extract top-level import names from Python source using AST.

    Handles ``import X``, ``import X.Y``, ``from X import Y``,
    relative imports (``from . import Y`` — skipped), and imports
    nested inside functions / classes / try-except blocks.
    """

    def __init__(self) -> None:
        self.imports: list[tuple[str, Path]] = []

    def scan_file(self, filepath: Path) -> list[str]:
        """Parse a single Python file and return top-level import names.

        Args:
            filepath: Path to the ``.py`` file.

        Returns:
            List of top-level import names found in this file. Relative
            imports (``from . import X``) are skipped because they refer to
            project-local modules, not third-party packages.
        """
        try:
            source = filepath.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return []

        try:
            tree = ast.parse(source, filename=str(filepath))
        except SyntaxError:
            # Fall back to a regex scan for files with syntax errors
            # (e.g. generated files, stubs, notebooks exported as .py).
            return self._regex_scan(source)

        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name:
                        names.append(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                # Skip relative imports (level > 0) — they are project-local.
                if node.level and node.level > 0:
                    continue
                if node.module:
                    names.append(node.module.split(".")[0])
        return names

    def _regex_scan(self, source: str) -> list[str]:
        """Fallback regex-based import extraction for unparseable files.

        Less accurate than AST but handles syntactically-broken sources.
        """
        names: list[str] = []
        pattern = re.compile(
            r"^\s*(?:from\s+(?P<from_mod>[a-zA-Z_][\w.]*)\s+import|"
            r"import\s+(?P<imp_mod>[a-zA-Z_][\w.]*))",
            re.MULTILINE,
        )
        for match in pattern.finditer(source):
            mod = match.group("from_mod") or match.group("imp_mod")
            if mod:
                top = mod.lstrip(".")
                if top and not top.startswith("."):
                    names.append(top.split(".")[0])
        return names


# ---------------------------------------------------------------------------
# Default known-indirect dependencies (common packaging-only deps)
# ---------------------------------------------------------------------------

# These packages are commonly declared but rarely imported directly — they are
# used indirectly as plugins, build tools, type stubs, or data files.  We assign
# them LOW confidence by default to avoid noisy false positives.
KNOWN_INDIRECT_PACKAGES: frozenset[str] = frozenset(
    {
        # Build tooling (never imported at runtime)
        "setuptools",
        "pip",
        "wheel",
        "build",
        "hatchling",
        "flit-core",
        "flit",
        "poetry",
        "poetry-core",
        "uv",
        "uv-build",
        "setuptools-scm",
        # Type stubs (PEP 561)
        "types-requests",
        "types-python-dateutil",
        "types-pyyaml",
        "types-setuptools",
        "types-protobuf",
        "types-docutils",
        "types-toml",
        "types-six",
        # Test-only deps commonly declared at top level
        "pytest",
        "pytest-cov",
        "pytest-asyncio",
        "pytest-mock",
        "pytest-xdist",
        "pytest-benchmark",
        "pytest-timeout",
        "pytest-rerunfailures",
        "hypothesis",
        "mock",
        "tox",
        "nox",
        "coverage",
        "pip-audit",
        # Linters / formatters (invoked as CLIs, not imported)
        "ruff",
        "black",
        "isort",
        "flake8",
        "mypy",
        "pyright",
        "ty",
        "pylint",
        "pyupgrade",
        "pre-commit",
        "prek",
        # Docs
        "sphinx",
        "myst-parser",
        "sphinx-rtd-theme",
        "sphinx-autodoc-typehints",
        "mkdocs",
        "mkdocs-material",
        # Packaging / metadata deps commonly used indirectly
        "packaging",
        "tomli",
        "tomli-w",
        "types-toml",
    }
)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------


class UnusedAnalyzer:
    """Main analyzer that ties scanning, mapping, and confidence together.

    The analyzer is pure (no network access by default) and deterministic —
    passing the same project path always produces the same result. The
    optional ``include_transitive`` mode may perform a PyPI lookup to
    detect transitive usage, but that path is off by default.
    """

    def __init__(self, config: UnusedConfig | None = None) -> None:
        self.config = config or UnusedConfig()
        self.stdlib = get_stdlib_modules()
        self.scanner = ImportScanner()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyze(self, project_path: str | Path) -> UnusedResult:
        """Run the unused-dependency analysis on a project.

        Args:
            project_path: Root directory of the project to analyze.

        Returns:
            An :class:`UnusedResult` with unused and (optionally) undeclared
            findings, plus metadata about the scan.
        """
        project_path = Path(project_path).resolve()
        result = UnusedResult(project_path=str(project_path))

        if not project_path.is_dir():
            result.errors.append(f"Not a directory: {project_path}")
            return result

        # 1. Discover declared dependencies
        dependencies, manifest_files = discover_dependencies(project_path)
        result.manifest_files = manifest_files
        result.declared = len(dependencies)
        declared_names = {dep.name for dep in dependencies}
        {dep.name: dep.version for dep in dependencies}
        declared_in_files: dict[str, list[str]] = {}
        for dep in dependencies:
            declared_in_files.setdefault(dep.name, []).extend(
                self._find_manifest_for_dep(dep.name, manifest_files)
            )

        # 2. Collect project-local module names (to avoid flagging self-imports)
        local_modules = self._collect_local_modules(project_path)

        # 3. Scan Python source files for imports
        imported_map: dict[str, set[Path]] = {}
        files_scanned = 0

        for py_file in self._iter_python_files(project_path):
            if files_scanned >= self.config.max_files:
                result.errors.append(
                    f"Reached max_files limit ({self.config.max_files}); "
                    f"some files were not scanned."
                )
                break
            files_scanned += 1
            for import_name in self.scanner.scan_file(py_file):
                if not import_name or import_name in self.stdlib:
                    continue
                if import_name in local_modules:
                    continue
                imported_map.setdefault(import_name, set()).add(py_file)

        result.files_scanned = files_scanned

        # Map import names to distribution names
        imported_packages: dict[str, set[Path]] = {}
        for import_name, files in imported_map.items():
            dist = resolve_import_to_package(import_name)
            if dist is None:
                continue
            imported_packages.setdefault(dist, set()).update(files)

        result.imported = sorted(imported_packages.keys())

        # 4. Compute unused (declared but not imported)
        imported_set = set(imported_packages.keys())
        for dep in dependencies:
            if dep.name in imported_set:
                continue  # definitely used
            finding = self._make_finding(
                dep=dep,
                declared_in_files=declared_in_files.get(dep.name, []),
                imported_set=imported_set,
            )
            if self._meets_threshold(finding.confidence):
                result.unused.append(finding)

        # Sort by confidence (HIGH first), then name
        order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        result.unused.sort(key=lambda f: (order[f.confidence], f.name))

        # 5. Optionally compute undeclared (imported but not declared)
        if self.config.include_undeclared:
            for import_name, files in imported_map.items():
                top = import_name.split(".")[0]
                if top in self.stdlib or top in local_modules:
                    continue
                resolved = resolve_import_to_package(import_name) or normalize_package_name(top)
                if resolved in declared_names:
                    continue
                result.undeclared.append(
                    UndeclaredFinding(
                        import_name=top,
                        resolved_package=resolved,
                        used_in=sorted(str(f.relative_to(project_path)) for f in files),
                    )
                )
            result.undeclared.sort(key=lambda f: f.import_name)

        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _find_manifest_for_dep(self, dep_name: str, manifest_files: list[str]) -> list[str]:
        """Best-effort attribution of a dep to its manifest file(s).

        Returns the manifest files that likely contain the declaration.
        We don't re-parse the manifests here; we rely on the scanner output
        which already tells us which files were scanned.
        """
        return list(manifest_files)

    def _collect_local_modules(self, project_path: Path) -> set[str]:
        """Collect project-local module names to avoid self-import false positives.

        Returns a set of top-level module names that belong to the project,
        determined from ``__init__.py`` files and top-level ``.py`` files.
        """
        local: set[str] = set()
        # src/ layout
        src_dir = project_path / "src"
        scan_roots: list[Path] = []
        if src_dir.is_dir():
            scan_roots.append(src_dir)
        scan_roots.append(project_path)

        for root in scan_roots:
            try:
                for child in root.iterdir():
                    if self._is_excluded(child):
                        continue
                    if child.is_file() and child.suffix == ".py":
                        local.add(normalize_package_name(child.stem))
                    elif child.is_dir() and (child / "__init__.py").exists():
                        local.add(normalize_package_name(child.name))
            except OSError:
                continue
        return local

    def _iter_python_files(self, project_path: Path):
        """Yield Python files under the project, respecting exclusions.

        Excludes directories in :attr:`UnusedConfig.exclude_dirs` and paths
        matching any pattern in :attr:`UnusedConfig.exclude_patterns`.
        """
        exclude_dirs = self.config.exclude_dirs
        exclude_patterns = self.config.exclude_patterns

        for py_file in project_path.rglob("*.py"):
            # Directory exclusions
            if any(part in exclude_dirs for part in py_file.parts):
                continue
            # Glob pattern exclusions
            if exclude_patterns:
                rel = py_file.relative_to(project_path)
                str(rel)
                if any(rel.match(p) for p in exclude_patterns):
                    continue
            yield py_file

    def _is_excluded(self, path: Path) -> bool:
        """Check whether a top-level path is in the exclude set."""
        return path.name in self.config.exclude_dirs

    def _make_finding(
        self,
        dep: ParsedDependency,
        declared_in_files: list[str],
        imported_set: set[str],
    ) -> UnusedFinding:
        """Build an :class:`UnusedFinding` with a confidence score.

        Confidence heuristics (ordered, first match wins):

        1. **LOW** — package is in :data:`KNOWN_INDIRECT_PACKAGES` (commonly
           declared for tooling, type stubs, or transitive-only use).
        2. **MEDIUM** — package name appears as a prefix of an imported package
           (e.g. ``flask`` declared, ``flask-login`` imported) — likely a
           transitive-only use.
        3. **HIGH** — no evidence of indirect or transitive use.
        """
        confidence = Confidence.HIGH
        reason = "No import statement found anywhere in the project source."

        norm_name = normalize_package_name(dep.name)

        if norm_name in KNOWN_INDIRECT_PACKAGES:
            confidence = Confidence.LOW
            reason = (
                "No direct import found, but this package is commonly used "
                "indirectly as build tooling, type stub, test runner, or linter."
            )
        else:
            # Heuristic: prefix match suggests transitive use.
            # E.g. declared "flask", imported "flask-wtf" -> flask is still used.
            for imported in imported_set:
                if imported == norm_name:
                    continue
                if imported.startswith(norm_name + "-") or imported.startswith(norm_name + "_"):
                    confidence = Confidence.MEDIUM
                    reason = (
                        f"No direct import of '{norm_name}' found, but '{imported}' "
                        f"is imported — '{norm_name}' may be pulled in transitively."
                    )
                    break

        return UnusedFinding(
            name=norm_name,
            declared_version=dep.version,
            declared_in=declared_in_files,
            confidence=confidence,
            reason=reason,
            imported_indirectly=(confidence != Confidence.HIGH),
        )

    def _meets_threshold(self, confidence: Confidence) -> bool:
        """Check whether a confidence level meets the configured threshold."""
        order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        return order[confidence] <= order[self.config.confidence_threshold]


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


_CONF_STYLES: dict[Confidence, tuple[str, str]] = {
    Confidence.HIGH: ("●", "red"),
    Confidence.MEDIUM: ("◑", "yellow"),
    Confidence.LOW: ("○", "dim"),
}


def render_unused_table(
    result: UnusedResult,
    console: Console | None = None,
) -> None:
    """Render the unused-dependency report as a Rich table.

    Args:
        result: The analysis result.
        console: Rich console to write to (created if not provided).
    """
    if console is None:
        console = Console()

    if not result.unused and not result.undeclared:
        console.print()
        console.print(
            Panel(
                "[green]No unused dependencies detected.[/green]\n\n"
                f"Scanned {result.files_scanned} Python files across "
                f"{result.project_path}.",
                title="[bold]depcheck unused[/bold]",
                border_style="green",
            )
        )
        return

    console.print()
    console.print("[bold]depcheck unused[/bold] — Unused dependency analysis")
    console.print(
        f"Scanned {result.files_scanned} files · {result.declared} declared · "
        f"{len(result.imported)} imported"
    )
    console.print()

    if result.unused:
        table = Table(title="Declared but not imported", show_lines=False, pad_edge=False)
        table.add_column("Package", style="bold", no_wrap=True)
        table.add_column("Version", style="dim")
        table.add_column("Confidence", justify="center")
        table.add_column("Reason", overflow="fold")

        for finding in result.unused:
            icon, color = _CONF_STYLES.get(finding.confidence, ("?", "white"))
            table.add_row(
                finding.name,
                finding.declared_version or "—",
                f"[{color}]{icon} {finding.confidence.value}[/{color}]",
                finding.reason,
            )
        console.print(table)
        console.print()

    if result.undeclared:
        u_table = Table(title="Imported but not declared", show_lines=False, pad_edge=False)
        u_table.add_column("Import", style="bold", no_wrap=True)
        u_table.add_column("Likely package", style="cyan")
        u_table.add_column("Used in", overflow="fold")

        for finding in result.undeclared:
            files_str = ", ".join(finding.used_in[:3])
            if len(finding.used_in) > 3:
                files_str += f" (+{len(finding.used_in) - 3} more)"
            u_table.add_row(finding.import_name, finding.resolved_package, files_str)
        console.print(u_table)
        console.print()

    # Legend
    console.print("[dim]Confidence: ● high · ◑ medium · ○ low[/dim]")
    console.print(
        "[dim]High = no evidence of use · Medium = possibly transitive · "
        "Low = commonly indirect[/dim]"
    )


def render_unused_json(
    result: UnusedResult,
    console: Console | None = None,
) -> None:
    """Render the unused-dependency report as JSON.

    Args:
        result: The analysis result.
        console: Rich console to write to (created if not provided).
    """
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(json.dumps(result.to_dict(), indent=2, default=str))


def determine_unused_exit_code(
    result: UnusedResult,
    fail_on: str | None = None,
) -> int:
    """Determine the exit code for the unused command.

    Args:
        result: The analysis result.
        fail_on: One of ``"high"``, ``"medium"``, ``"low"``, ``"any"`` or
            ``None``. When set, returns 1 if any finding meets the threshold.

    Returns:
        ``0`` if no findings meet the threshold, ``1`` otherwise.
    """
    if fail_on is None:
        return 0
    fail_on_lower = fail_on.lower()

    if fail_on_lower == "any":
        return 1 if (result.unused or result.undeclared) else 0

    threshold_map = {
        "high": Confidence.HIGH,
        "medium": Confidence.MEDIUM,
        "low": Confidence.LOW,
    }
    threshold = threshold_map.get(fail_on_lower)
    if threshold is None:
        return 0

    order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
    target = order[threshold]

    for finding in result.unused:
        if order[finding.confidence] <= target:
            return 1
    return 0
