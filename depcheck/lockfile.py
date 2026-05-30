"""Lockfile analysis and management for Python projects.

Parses pip freeze output, requirements.txt with pinned versions,
Pipfile.lock, and poetry.lock files. Detects unpinned dependencies,
hash mismatches, version drift from manifest, and generates
lockfile-diff reports. Also integrates with pip-audit for lockfile
security scanning.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import Version


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PIP_FREEZE_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)$"
)
PIP_FREEZE_EDITABLE_RE = re.compile(
    r"^(-e\s+|[A-Za-z0-9_.-]+ @ )(.+)$"
)
REQUIREMENT_LINE_RE = re.compile(
    r"^([A-Za-z0-9_.-]+)\s*(.*)$"
)
EXTRA_INDEX_RE = re.compile(
    r"^--extra-index-url\s+(.+)$"
)
INDEX_URL_RE = re.compile(
    r"^--index-url\s+(.+)$"
)
HASH_RE = re.compile(
    r"--hash=(\w+):([a-f0-9]+)"
)
ENV_MARKER_RE = re.compile(
    r";\s*(.+)$"
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class LockedPackage:
    """A package entry from a lockfile."""

    name: str
    version: str
    source: str = ""  # pypi, url, git, file, etc.
    url: str = ""
    hashes: list[str] = field(default_factory=list)
    extras: list[str] = field(default_factory=list)
    markers: str = ""  # environment markers
    is_editable: bool = False
    is_direct: bool = False  # directly specified vs transitive

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "source": self.source,
            "url": self.url,
            "hashes": self.hashes,
            "extras": self.extras,
            "markers": self.markers,
            "is_editable": self.is_editable,
            "is_direct": self.is_direct,
        }


@dataclass
class ManifestRequirement:
    """A requirement from the manifest (requirements.txt, pyproject.toml)."""

    name: str
    specifier: str  # e.g., ">=1.0,<2.0"
    extras: list[str] = field(default_factory=list)
    markers: str = ""
    is_pinned: bool = False
    has_hash: bool = False
    line_number: int = 0
    raw_line: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "specifier": self.specifier,
            "extras": self.extras,
            "markers": self.markers,
            "is_pinned": self.is_pinned,
            "has_hash": self.has_hash,
            "line_number": self.line_number,
        }


@dataclass
class UnpinnedDependency:
    """A dependency that is not properly pinned."""

    name: str
    issue: str  # "no_version", "range_specifier", "no_hash", "editable"
    severity: str  # "high", "medium", "low"
    current_version: str | None = None
    specifier: str | None = None
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "issue": self.issue,
            "severity": self.severity,
            "current_version": self.current_version,
            "specifier": self.specifier,
            "recommendation": self.recommendation,
        }


@dataclass
class DriftEntry:
    """A drift between manifest requirement and lockfile version."""

    name: str
    manifest_specifier: str
    locked_version: str
    drift_type: str  # "within_range", "not_pinned", "version_mismatch"
    is_within_range: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "manifest_specifier": self.manifest_specifier,
            "locked_version": self.locked_version,
            "drift_type": self.drift_type,
            "is_within_range": self.is_within_range,
        }


@dataclass
class HashMismatch:
    """A hash mismatch in a lockfile entry."""

    name: str
    version: str
    expected_hash: str
    algorithm: str
    issue: str  # "missing_hash", "hash_mismatch", "no_hashes_at_all"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "expected_hash": self.expected_hash,
            "algorithm": self.algorithm,
            "issue": self.issue,
        }


@dataclass
class LockfileReport:
    """Complete analysis report for a lockfile."""

    path: str
    lockfile_type: str  # "pip_freeze", "requirements_txt", "pipfile_lock", "poetry_lock"
    packages: list[LockedPackage] = field(default_factory=list)
    manifest_requirements: list[ManifestRequirement] = field(default_factory=list)
    unpinned: list[UnpinnedDependency] = field(default_factory=list)
    drift: list[DriftEntry] = field(default_factory=list)
    hash_issues: list[HashMismatch] = field(default_factory=list)
    total_packages: int = 0
    direct_packages: int = 0
    transitive_packages: int = 0
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    errors: list[str] = field(default_factory=list)

    @property
    def is_healthy(self) -> bool:
        """Check if the lockfile has no issues."""
        return (
            not self.unpinned
            and not self.drift
            and not self.hash_issues
            and not self.errors
        )

    @property
    def high_severity_count(self) -> int:
        return sum(1 for u in self.unpinned if u.severity == "high")

    @property
    def medium_severity_count(self) -> int:
        return sum(1 for u in self.unpinned if u.severity == "medium")

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "lockfile_type": self.lockfile_type,
            "total_packages": self.total_packages,
            "direct_packages": self.direct_packages,
            "transitive_packages": self.transitive_packages,
            "unpinned": [u.to_dict() for u in self.unpinned],
            "drift": [d.to_dict() for d in self.drift],
            "hash_issues": [h.to_dict() for h in self.hash_issues],
            "is_healthy": self.is_healthy,
            "timestamp": self.timestamp,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def detect_lockfile_type(path: Path) -> str | None:
    """Detect the type of lockfile at the given path.

    Returns one of: "pip_freeze", "requirements_txt", "pipfile_lock",
    "poetry_lock", or None if unrecognized.
    """
    name = path.name.lower()
    if name == "pipfile.lock":
        return "pipfile_lock"
    if name == "poetry.lock":
        return "poetry_lock"
    if name in ("requirements.txt", "requirements.lock", "requirements-dev.txt",
                "requirements-prod.txt", "requirements-dev.lock",
                "requirements.txt.lock"):
        return "requirements_txt"
    # Check content for pip-freeze signature
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")[:2000]
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
        # If all non-comment lines match Package==Version, it's pip freeze format
        if lines and all(PIP_FREEZE_RE.match(l) for l in lines):
            return "pip_freeze"
    except Exception:
        pass
    return None


def find_lockfiles(project_path: Path) -> list[Path]:
    """Find all lockfile candidates in a project directory."""
    candidates: list[Path] = []
    lockfile_names = [
        "requirements.txt",
        "requirements.lock",
        "requirements-dev.txt",
        "requirements-prod.txt",
        "Pipfile.lock",
        "poetry.lock",
    ]
    for name in lockfile_names:
        p = project_path / name
        if p.exists() and p.is_file():
            candidates.append(p)

    # Also check for *.txt files that look like requirements files
    for txt in project_path.glob("requirements*.txt"):
        if txt not in candidates:
            candidates.append(txt)

    return candidates


def parse_pip_freeze(content: str) -> list[LockedPackage]:
    """Parse pip freeze output (Package==Version format)."""
    packages: list[LockedPackage] = []

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Skip editable installs
        if line.startswith("-e ") or PIP_FREEZE_EDITABLE_RE.match(line):
            continue

        match = PIP_FREEZE_RE.match(line)
        if match:
            name, version = match.group(1), match.group(2)
            packages.append(
                LockedPackage(
                    name=name,
                    version=version,
                    source="pypi",
                )
            )

    return packages


def parse_requirements_txt(content: str) -> tuple[list[LockedPackage], list[ManifestRequirement]]:
    """Parse a requirements.txt file.

    Returns both locked packages (pinned deps) and manifest requirements
    (all deps including unpinned ones).
    """
    packages: list[LockedPackage] = []
    requirements: list[ManifestRequirement] = []

    for i, line in enumerate(content.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            # Handle --index-url, --extra-index-url, etc.
            continue

        # Extract hashes
        hashes: list[str] = []
        hash_matches = HASH_RE.findall(line)
        for algo, digest in hash_matches:
            hashes.append(f"{algo}:{digest}")

        # Remove hashes and options from the line for parsing
        clean_line = re.sub(r"\s*--hash=\S+", "", line)
        clean_line = re.sub(r"\s*--\S+", "", clean_line).strip()

        # Split off environment markers
        markers = ""
        marker_match = ENV_MARKER_RE.search(clean_line)
        if marker_match:
            markers = marker_match.group(1).strip()
            clean_line = clean_line[: marker_match.start()].strip()

        # Parse name and specifier
        match = REQUIREMENT_LINE_RE.match(clean_line)
        if not match:
            continue

        name = match.group(1)
        rest = match.group(2).strip()

        # Handle extras
        extras: list[str] = []
        extras_match = re.match(r"\[([^\]]+)\]", rest)
        if extras_match:
            extras = [e.strip() for e in extras_match.group(1).split(",")]
            rest = rest[extras_match.end():].strip()

        # Determine if pinned
        is_pinned = False
        specifier = ""
        if rest.startswith("=="):
            is_pinned = True
            specifier = rest
            # Extract version from ==X
            version = rest[2:].split(",")[0].strip()
            packages.append(
                LockedPackage(
                    name=name,
                    version=version,
                    source="pypi",
                    hashes=hashes,
                    extras=extras,
                    markers=markers,
                    is_direct=True,
                )
            )
        elif rest:
            specifier = rest

        requirements.append(
            ManifestRequirement(
                name=name,
                specifier=specifier,
                extras=extras,
                markers=markers,
                is_pinned=is_pinned,
                has_hash=bool(hashes),
                line_number=i,
                raw_line=line,
            )
        )

    return packages, requirements


def parse_pipfile_lock(content: str) -> list[LockedPackage]:
    """Parse a Pipfile.lock file."""
    packages: list[LockedPackage] = []

    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return packages

    # Default packages
    for name, info in data.get("default", {}).items():
        if isinstance(info, dict):
            version = info.get("version", "").replace("==", "")
            hashes = info.get("hashes", [])
            packages.append(
                LockedPackage(
                    name=name,
                    version=version,
                    source=info.get("source", "pypi"),
                    hashes=hashes,
                    is_direct=True,
                )
            )

    # Develop packages
    for name, info in data.get("develop", {}).items():
        if isinstance(info, dict):
            version = info.get("version", "").replace("==", "")
            hashes = info.get("hashes", [])
            packages.append(
                LockedPackage(
                    name=name,
                    version=version,
                    source=info.get("source", "pypi"),
                    hashes=hashes,
                    is_direct=True,
                )
            )

    return packages


def parse_poetry_lock(content: str) -> list[LockedPackage]:
    """Parse a poetry.lock file (TOML format).

    Note: poetry.lock is TOML, but we parse it with a simple
    state-machine parser to avoid adding a TOML dependency for
    Python < 3.11 (where tomllib isn't available).
    """
    packages: list[LockedPackage] = []
    current_pkg: dict[str, Any] = {}
    in_package = False

    for line in content.splitlines():
        line = line.strip()

        if line == "[[package]]":
            # Save previous package
            if current_pkg and "name" in current_pkg:
                packages.append(
                    LockedPackage(
                        name=current_pkg.get("name", ""),
                        version=current_pkg.get("version", ""),
                        source=current_pkg.get("source", {}).get("type", "pypi") if isinstance(current_pkg.get("source"), dict) else "pypi",
                        url=current_pkg.get("source", {}).get("url", "") if isinstance(current_pkg.get("source"), dict) else "",
                    )
                )
            current_pkg = {}
            in_package = True
            continue

        if in_package and line.startswith("["):
            # New section — end of package
            if current_pkg and "name" in current_pkg:
                packages.append(
                    LockedPackage(
                        name=current_pkg.get("name", ""),
                        version=current_pkg.get("version", ""),
                        source="pypi",
                    )
                )
            current_pkg = {}
            in_package = line == "[[package]]"
            continue

        if in_package and "=" in line:
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip().strip('"')

            if key == "name":
                current_pkg["name"] = value
            elif key == "version":
                current_pkg["version"] = value

    # Don't forget the last package
    if current_pkg and "name" in current_pkg:
        packages.append(
            LockedPackage(
                name=current_pkg.get("name", ""),
                version=current_pkg.get("version", ""),
                source="pypi",
            )
        )

    return packages


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


def analyze_unpinned(requirements: list[ManifestRequirement]) -> list[UnpinnedDependency]:
    """Analyze manifest requirements for unpinned dependencies."""
    unpinned: list[UnpinnedDependency] = []

    for req in requirements:
        # No version at all
        if not req.specifier:
            unpinned.append(
                UnpinnedDependency(
                    name=req.name,
                    issue="no_version",
                    severity="high",
                    specifier=req.specifier,
                    recommendation=f"Pin {req.name} to a specific version: {req.name}==X.Y.Z",
                )
            )
        # Not pinned with ==
        elif not req.specifier.startswith("=="):
            unpinned.append(
                UnpinnedDependency(
                    name=req.name,
                    issue="range_specifier",
                    severity="medium",
                    specifier=req.specifier,
                    recommendation=f"Pin {req.name} to exact version: {req.name}==X.Y.Z",
                )
            )

        # No hash (lower severity)
        if not req.has_hash and req.is_pinned:
            # Only flag if already pinned but missing hash
            existing = next((u for u in unpinned if u.name == req.name), None)
            if existing is None:
                unpinned.append(
                    UnpinnedDependency(
                        name=req.name,
                        issue="no_hash",
                        severity="low",
                        current_version=req.specifier.replace("==", "") if req.specifier.startswith("==") else None,
                        specifier=req.specifier,
                        recommendation=f"Add hash to {req.name}: {req.raw_line} --hash=sha256:HEX",
                    )
                )

    return unpinned


def analyze_drift(
    requirements: list[ManifestRequirement],
    locked_packages: list[LockedPackage],
) -> list[DriftEntry]:
    """Analyze drift between manifest requirements and locked versions."""
    drift: list[DriftEntry] = []

    locked_map = {p.name.lower(): p for p in locked_packages}

    for req in requirements:
        pkg = locked_map.get(req.name.lower())
        if pkg is None:
            continue

        if req.is_pinned:
            # Check if locked version matches pinned version
            pinned_version = req.specifier.replace("==", "").split(",")[0].strip()
            if pkg.version != pinned_version:
                drift.append(
                    DriftEntry(
                        name=req.name,
                        manifest_specifier=req.specifier,
                        locked_version=pkg.version,
                        drift_type="version_mismatch",
                        is_within_range=False,
                    )
                )
        elif req.specifier:
            # Check if locked version is within range
            try:
                spec = SpecifierSet(req.specifier)
                locked_ver = Version(pkg.version)
                is_within = locked_ver in spec
                drift.append(
                    DriftEntry(
                        name=req.name,
                        manifest_specifier=req.specifier,
                        locked_version=pkg.version,
                        drift_type="within_range" if is_within else "version_mismatch",
                        is_within_range=is_within,
                    )
                )
            except Exception:
                drift.append(
                    DriftEntry(
                        name=req.name,
                        manifest_specifier=req.specifier,
                        locked_version=pkg.version,
                        drift_type="not_pinned",
                        is_within_range=False,
                    )
                )

    return drift


def analyze_hashes(locked_packages: list[LockedPackage]) -> list[HashMismatch]:
    """Analyze hash issues in locked packages."""
    issues: list[HashMismatch] = []

    for pkg in locked_packages:
        if pkg.is_editable:
            continue

        if not pkg.hashes:
            issues.append(
                HashMismatch(
                    name=pkg.name,
                    version=pkg.version,
                    expected_hash="",
                    algorithm="sha256",
                    issue="no_hashes_at_all",
                )
            )

    return issues


# ---------------------------------------------------------------------------
# pip-audit integration
# ---------------------------------------------------------------------------


@dataclass
class PipAuditResult:
    """Result from pip-audit security scan."""

    packages_scanned: int = 0
    vulnerabilities_found: int = 0
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    skipped: bool = False
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "packages_scanned": self.packages_scanned,
            "vulnerabilities_found": self.vulnerabilities_found,
            "vulnerabilities": self.vulnerabilities,
            "skipped": self.skipped,
            "error": self.error,
        }


def run_pip_audit(requirements_path: Path | None = None) -> PipAuditResult:
    """Run pip-audit on a requirements file.

    pip-audit is a PyPA tool for scanning Python requirements for
    known vulnerabilities using the PyPI Advisory Database and
    OSV database. This is an optional integration — if pip-audit
    is not installed, we gracefully skip.
    """
    result = PipAuditResult()

    cmd = [sys.executable, "-m", "pip_audit", "--format", "json"]
    if requirements_path:
        cmd.extend(["-r", str(requirements_path)])
    else:
        cmd.append(".")  # audit current project

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )

        if proc.returncode == 0:
            try:
                data = json.loads(proc.stdout)
                result.packages_scanned = len(data.get("packages", []))
                deps = data.get("dependencies", [])
                result.vulnerabilities_found = len(deps)
                result.vulnerabilities = deps
            except json.JSONDecodeError:
                # pip-audit might output nothing if no deps
                pass
        elif proc.returncode == 1:
            # Vulnerabilities found
            try:
                data = json.loads(proc.stdout)
                deps = data.get("dependencies", [])
                result.vulnerabilities_found = len(deps)
                result.vulnerabilities = deps
            except json.JSONDecodeError:
                result.error = proc.stderr[:500] if proc.stderr else "pip-audit returned 1"
        else:
            result.error = f"pip-audit exited with code {proc.returncode}"

    except FileNotFoundError:
        result.skipped = True
        result.error = "pip-audit not installed"
    except subprocess.TimeoutExpired:
        result.skipped = True
        result.error = "pip-audit timed out"
    except Exception as e:
        result.skipped = True
        result.error = str(e)[:200]

    return result


# ---------------------------------------------------------------------------
# Main lockfile analysis
# ---------------------------------------------------------------------------


def analyze_lockfile(path: Path, manifest_path: Path | None = None) -> LockfileReport:
    """Analyze a lockfile and produce a comprehensive report.

    Args:
        path: Path to the lockfile.
        manifest_path: Optional path to the manifest file (for drift analysis).

    Returns:
        LockfileReport with analysis results.
    """
    report = LockfileReport(path=str(path), lockfile_type="unknown")
    lockfile_type = detect_lockfile_type(path)

    if not lockfile_type:
        report.errors.append(f"Could not determine lockfile type for {path}")
        return report

    report.lockfile_type = lockfile_type

    # Read and parse lockfile
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        report.errors.append(f"Failed to read {path}: {e}")
        return report

    if lockfile_type == "pipfile_lock":
        report.packages = parse_pipfile_lock(content)
    elif lockfile_type == "poetry_lock":
        report.packages = parse_poetry_lock(content)
    elif lockfile_type in ("requirements_txt", "pip_freeze"):
        locked, reqs = parse_requirements_txt(content)
        report.packages = locked
        report.manifest_requirements = reqs
        report.unpinned = analyze_unpinned(reqs)
    else:
        report.errors.append(f"Unsupported lockfile type: {lockfile_type}")
        return report

    report.total_packages = len(report.packages)
    report.direct_packages = sum(1 for p in report.packages if p.is_direct)
    report.transitive_packages = report.total_packages - report.direct_packages

    # Hash analysis
    report.hash_issues = analyze_hashes(report.packages)

    # Drift analysis (if manifest is separate)
    if manifest_path and manifest_path.exists() and lockfile_type != "requirements_txt":
        try:
            manifest_content = manifest_path.read_text(encoding="utf-8", errors="ignore")
            _, reqs = parse_requirements_txt(manifest_content)
            report.manifest_requirements = reqs
            report.drift = analyze_drift(reqs, report.packages)
        except Exception as e:
            report.errors.append(f"Failed to read manifest {manifest_path}: {e}")
    elif lockfile_type == "requirements_txt" and report.manifest_requirements:
        report.drift = analyze_drift(report.manifest_requirements, report.packages)

    return report


def analyze_project_lockfiles(project_path: str = ".") -> list[LockfileReport]:
    """Find and analyze all lockfiles in a project.

    This is the main entry point for the `depcheck lockfile` command.
    """
    project = Path(project_path).resolve()
    lockfiles = find_lockfiles(project)

    if not lockfiles:
        # Try generating a pip freeze report
        try:
            proc = subprocess.run(
                [sys.executable, "-m", "pip", "freeze"],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=str(project),
            )
            if proc.returncode == 0 and proc.stdout.strip():
                packages = parse_pip_freeze(proc.stdout)
                report = LockfileReport(
                    path="<pip freeze>",
                    lockfile_type="pip_freeze",
                    packages=packages,
                    total_packages=len(packages),
                    direct_packages=len(packages),  # can't distinguish
                )
                return [report]
        except Exception:
            pass

        return []

    reports: list[LockfileReport] = []
    for lf in lockfiles:
        # Try to find manifest for drift analysis
        manifest: Path | None = None
        if lf.name == "Pipfile.lock":
            manifest = project / "Pipfile"
        elif lf.name == "poetry.lock":
            manifest = project / "pyproject.toml"
        elif lf.name in ("requirements.lock", "requirements.txt.lock"):
            manifest = project / "requirements.txt"

        report = analyze_lockfile(lf, manifest_path=manifest)
        reports.append(report)

    return reports


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_lockfile_table(reports: list[LockfileReport], *, console: Any = None) -> None:
    """Render lockfile analysis as a Rich table."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    if console is None:
        console = Console()

    for report in reports:
        # Header
        status_icon = "✓" if report.is_healthy else "✗"
        status_color = "green" if report.is_healthy else "red"

        header = Text()
        header.append(f"{status_icon} ", style=status_color)
        header.append(f"{report.path} ", style="bold")
        header.append(f"({report.lockfile_type})", style="dim")
        header.append(f"\n  {report.total_packages} packages", style="dim")
        if report.direct_packages:
            header.append(
                f" ({report.direct_packages} direct, {report.transitive_packages} transitive)",
                style="dim",
            )

        console.print(Panel(header, title="Lockfile Analysis", border_style=status_color))

        # Unpinned dependencies
        if report.unpinned:
            unpin_table = Table(title="Unpinned Dependencies", show_lines=True)
            unpin_table.add_column("Package", style="bold")
            unpin_table.add_column("Issue")
            unpin_table.add_column("Severity", justify="center")
            unpin_table.add_column("Recommendation")

            for u in report.unpinned:
                sev_color = {"high": "red", "medium": "yellow", "low": "dim"}.get(
                    u.severity, "white"
                )
                unpin_table.add_row(
                    u.name,
                    u.issue.replace("_", " ").title(),
                    f"[{sev_color}]{u.severity}[/{sev_color}]",
                    u.recommendation[:60],
                )

            console.print(unpin_table)

        # Drift
        if report.drift:
            drift_table = Table(title="Version Drift", show_lines=False)
            drift_table.add_column("Package", style="bold")
            drift_table.add_column("Manifest Spec")
            drift_table.add_column("Locked Version")
            drift_table.add_column("In Range?", justify="center")

            for d in report.drift:
                range_icon = "✓" if d.is_within_range else "✗"
                range_color = "green" if d.is_within_range else "red"
                drift_table.add_row(
                    d.name,
                    d.manifest_specifier or "*",
                    d.locked_version,
                    f"[{range_color}]{range_icon}[/{range_color}]",
                )

            console.print(drift_table)

        # Hash issues
        if report.hash_issues:
            no_hash_count = sum(1 for h in report.hash_issues if h.issue == "no_hashes_at_all")
            if no_hash_count > 0:
                console.print(
                    f"\n[yellow]⚠ {no_hash_count} packages missing integrity hashes[/yellow]"
                )
                console.print(
                    "[dim]  Consider using pip-compile --generate-hashes "
                    "or pip install --require-hashes[/dim]"
                )

        # Errors
        for err in report.errors:
            console.print(f"[red]Error: {err}[/red]")

        console.print()


def render_lockfile_json(reports: list[LockfileReport], *, console: Any = None) -> None:
    """Render lockfile analysis as JSON."""
    from rich.console import Console

    if console is None:
        console = Console(force_terminal=False, no_color=True)

    data = [r.to_dict() for r in reports]
    console.print(json.dumps(data, indent=2))


def render_pip_audit_table(audit_result: PipAuditResult, *, console: Any = None) -> None:
    """Render pip-audit results as a Rich table."""
    from rich.console import Console
    from rich.table import Table

    if console is None:
        console = Console()

    if audit_result.skipped:
        console.print(f"[dim]pip-audit skipped: {audit_result.error}[/dim]")
        return

    if audit_result.error and not audit_result.vulnerabilities_found:
        console.print(f"[yellow]pip-audit error: {audit_result.error}[/yellow]")
        return

    if audit_result.vulnerabilities_found == 0:
        console.print("[green]✓ pip-audit: No known vulnerabilities found[/green]")
        return

    table = Table(title="pip-audit Vulnerabilities")
    table.add_column("Package", style="bold")
    table.add_column("Vuln ID")
    table.add_column("Severity")
    table.add_column("Description")
    table.add_column("Fix Version")

    for vuln in audit_result.vulnerabilities:
        # pip-audit JSON format varies; handle gracefully
        if isinstance(vuln, dict):
            name = vuln.get("package", {}).get("name", "unknown")
            vid = vuln.get("id", "unknown")
            sev = vuln.get("severity", "unknown")
            desc = vuln.get("description", "")[:60]
            fix = vuln.get("fix_versions", ["N/A"])[0] if vuln.get("fix_versions") else "N/A"
            sev_color = {"critical": "red", "high": "red", "medium": "yellow", "low": "green"}.get(
                str(sev).lower(), "white"
            )
            table.add_row(
                name,
                vid,
                f"[{sev_color}]{sev}[/{sev_color}]",
                desc,
                fix,
            )

    console.print(table)


# ---------------------------------------------------------------------------
# Freeze command — generate lockfile from current environment
# ---------------------------------------------------------------------------


def generate_freeze(project_path: str = ".", output_path: str | None = None) -> str:
    """Generate a requirements.txt freeze from the current environment.

    Args:
        project_path: Project directory (for context).
        output_path: Optional output file path. If None, returns the content.

    Returns:
        The freeze content as a string.
    """
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pip", "freeze"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=str(Path(project_path).resolve()),
        )
        content = proc.stdout
    except Exception as e:
        return f"# Error generating freeze: {e}\n"

    if output_path:
        Path(output_path).write_text(content, encoding="utf-8")
        return content

    return content


# ---------------------------------------------------------------------------
# Lockfile diff — compare two lockfiles
# ---------------------------------------------------------------------------


@dataclass
class LockfileDiff:
    """Difference between two lockfiles."""

    old_path: str
    new_path: str
    added: list[LockedPackage] = field(default_factory=list)
    removed: list[LockedPackage] = field(default_factory=list)
    changed: list[tuple[LockedPackage, LockedPackage]] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "old_path": self.old_path,
            "new_path": self.new_path,
            "added": [p.to_dict() for p in self.added],
            "removed": [p.to_dict() for p in self.removed],
            "changed": [
                {"old": old.to_dict(), "new": new.to_dict()}
                for old, new in self.changed
            ],
            "unchanged_count": self.unchanged_count,
        }


def diff_lockfiles(old_path: Path, new_path: Path) -> LockfileDiff:
    """Compare two lockfiles and return the differences."""
    old_type = detect_lockfile_type(old_path) or "requirements_txt"
    new_type = detect_lockfile_type(new_path) or "requirements_txt"

    # Parse both files
    old_content = old_path.read_text(encoding="utf-8", errors="ignore")
    new_content = new_path.read_text(encoding="utf-8", errors="ignore")

    old_packages: list[LockedPackage] = []
    new_packages: list[LockedPackage] = []

    if old_type == "pipfile_lock":
        old_packages = parse_pipfile_lock(old_content)
    elif old_type == "poetry_lock":
        old_packages = parse_poetry_lock(old_content)
    else:
        old_packages, _ = parse_requirements_txt(old_content)

    if new_type == "pipfile_lock":
        new_packages = parse_pipfile_lock(new_content)
    elif new_type == "poetry_lock":
        new_packages = parse_poetry_lock(new_content)
    else:
        new_packages, _ = parse_requirements_txt(new_content)

    # Build maps
    old_map = {p.name.lower(): p for p in old_packages}
    new_map = {p.name.lower(): p for p in new_packages}

    # Compute diff
    result = LockfileDiff(
        old_path=str(old_path),
        new_path=str(new_path),
    )

    # Added: in new but not in old
    for name, pkg in new_map.items():
        if name not in old_map:
            result.added.append(pkg)

    # Removed: in old but not in new
    for name, pkg in old_map.items():
        if name not in new_map:
            result.removed.append(pkg)

    # Changed: in both but different version
    for name, new_pkg in new_map.items():
        if name in old_map:
            old_pkg = old_map[name]
            if old_pkg.version != new_pkg.version:
                result.changed.append((old_pkg, new_pkg))
            else:
                result.unchanged_count += 1

    return result


def render_lockfile_diff_table(diff: LockfileDiff, *, console: Any = None) -> None:
    """Render a lockfile diff as a Rich table."""
    from rich.console import Console
    from rich.table import Table

    if console is None:
        console = Console()

    if not diff.has_changes:
        console.print("[green]No differences between lockfiles.[/green]")
        return

    table = Table(title="Lockfile Diff")
    table.add_column("Change", style="bold")
    table.add_column("Package", style="bold")
    table.add_column("Old Version", style="red")
    table.add_column("New Version", style="green")

    for pkg in diff.added:
        table.add_row("[green]Added[/green]", pkg.name, "—", pkg.version)

    for pkg in diff.removed:
        table.add_row("[red]Removed[/red]", pkg.name, pkg.version, "—")

    for old_pkg, new_pkg in diff.changed:
        table.add_row("[yellow]Changed[/yellow]", old_pkg.name, old_pkg.version, new_pkg.version)

    console.print(table)
    console.print(f"[dim]{diff.unchanged_count} unchanged packages[/dim]")
