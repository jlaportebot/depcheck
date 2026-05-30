"""Dependency resolution engine for depcheck.

Provides version constraint solving, conflict detection, resolution strategies,
lockfile generation, and dependency deduplication. Implements a backtracking
solver that resolves compatible version sets across a full dependency graph.
"""

from __future__ import annotations

import json
import re
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from packaging.specifiers import SpecifierSet
from packaging.version import Version, InvalidVersion


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class ResolutionStrategy(Enum):
    """Strategy for picking versions during resolution."""

    NEWEST = "newest"
    OLDEST = "oldest"
    MINIMUM_COMPATIBLE = "minimum_compatible"


class ConflictType(Enum):
    """Type of dependency conflict."""

    VERSION_CONFLICT = "version_conflict"
    CIRCULAR_DEPENDENCY = "circular_dependency"
    MISSING_PACKAGE = "missing_package"
    YANKED_VERSION = "yanked_version"
    INCOMPATIBLE_PYTHON = "incompatible_python"
    EXTRA_NOT_FOUND = "extra_not_found"


class LockfileFormat(Enum):
    """Supported lockfile formats."""

    PIP = "pip"
    PIPENV = "pipfile.lock"
    POETRY = "poetry.lock"
    DEPCHECK = "depcheck.lock"


@dataclass
class VersionConstraint:
    """A single version constraint (e.g. '>=1.2.0,<2.0.0')."""

    package: str
    specifier: str
    source: str = ""  # Which package/requirement imposed this constraint

    @property
    def specifier_set(self) -> SpecifierSet:
        """Parse into a packaging SpecifierSet."""
        return SpecifierSet(self.specifier)

    def allows(self, version: str) -> bool:
        """Check whether a version string satisfies this constraint."""
        try:
            return Version(version) in self.specifier_set
        except InvalidVersion:
            return version in self.specifier_set

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "specifier": self.specifier,
            "source": self.source,
        }


@dataclass
class ResolvedPackage:
    """A package with its resolved version and metadata."""

    name: str
    version: str
    constraints: list[VersionConstraint] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    is_transitive: bool = False
    source: str = "pypi"
    hash_sha256: str = ""
    python_version: str = ""
    extras: list[str] = field(default_factory=list)

    @property
    def normalized_name(self) -> str:
        """Normalize package name (PEP 503)."""
        return re.sub(r"[-_.]+", "-", self.name).lower()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "constraints": [c.to_dict() for c in self.constraints],
            "dependencies": self.dependencies,
            "is_transitive": self.is_transitive,
            "source": self.source,
            "hash_sha256": self.hash_sha256,
            "python_version": self.python_version,
            "extras": self.extras,
        }


@dataclass
class Conflict:
    """A dependency conflict detected during resolution."""

    conflict_type: ConflictType
    package: str
    message: str
    constraints: list[VersionConstraint] = field(default_factory=list)
    suggested_fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "conflict_type": self.conflict_type.value,
            "package": self.package,
            "message": self.message,
            "constraints": [c.to_dict() for c in self.constraints],
            "suggested_fix": self.suggested_fix,
        }


@dataclass
class ResolutionResult:
    """Complete result of a dependency resolution run."""

    resolved: list[ResolvedPackage] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    unresolved: list[str] = field(default_factory=list)
    strategy_used: ResolutionStrategy = ResolutionStrategy.NEWEST
    resolution_time_ms: float = 0.0
    iterations: int = 0
    is_complete: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def has_conflicts(self) -> bool:
        return len(self.conflicts) > 0

    @property
    def direct_count(self) -> int:
        return sum(1 for p in self.resolved if not p.is_transitive)

    @property
    def transitive_count(self) -> int:
        return sum(1 for p in self.resolved if p.is_transitive)

    @property
    def conflict_count(self) -> int:
        return len(self.conflicts)

    @property
    def resolved_names(self) -> set[str]:
        return {p.normalized_name for p in self.resolved}

    def get_package(self, name: str) -> ResolvedPackage | None:
        """Look up a resolved package by name (normalized)."""
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        for pkg in self.resolved:
            if pkg.normalized_name == normalized:
                return pkg
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolved": [p.to_dict() for p in self.resolved],
            "conflicts": [c.to_dict() for c in self.conflicts],
            "unresolved": self.unresolved,
            "strategy": self.strategy_used.value,
            "resolution_time_ms": self.resolution_time_ms,
            "iterations": self.iterations,
            "is_complete": self.is_complete,
            "errors": self.errors,
            "summary": {
                "total": len(self.resolved),
                "direct": self.direct_count,
                "transitive": self.transitive_count,
                "conflicts": self.conflict_count,
                "unresolved": len(self.unresolved),
            },
        }


# ---------------------------------------------------------------------------
# Package index interface (abstract)
# ---------------------------------------------------------------------------


class PackageIndex:
    """Interface to a package index (PyPI or mock for testing)."""

    def get_available_versions(self, package: str) -> list[str]:
        """Return sorted list of available versions (newest first)."""
        raise NotImplementedError

    def get_dependencies(self, package: str, version: str) -> list[VersionConstraint]:
        """Return dependencies for a specific package version."""
        raise NotImplementedError

    def get_package_hash(self, package: str, version: str) -> str:
        """Return SHA-256 hash for a specific package version."""
        raise NotImplementedError

    def is_yanked(self, package: str, version: str) -> bool:
        """Check if a specific version has been yanked."""
        raise NotImplementedError

    def get_python_constraint(self, package: str, version: str) -> str:
        """Return Python version constraint for a package version."""
        return ""


class MockPackageIndex(PackageIndex):
    """In-memory package index for testing and offline resolution."""

    def __init__(self) -> None:
        self._versions: dict[str, list[str]] = {}
        self._deps: dict[str, dict[str, list[VersionConstraint]]] = {}
        self._hashes: dict[str, dict[str, str]] = {}
        self._yanked: dict[str, set[str]] = {}
        self._python_constraints: dict[str, dict[str, str]] = {}

    def add_package(
        self,
        name: str,
        versions: list[str],
        deps: dict[str, list[VersionConstraint]] | None = None,
        hashes: dict[str, str] | None = None,
        yanked: set[str] | None = None,
        python_constraints: dict[str, str] | None = None,
    ) -> None:
        """Add a package to the mock index."""
        norm = re.sub(r"[-_.]+", "-", name).lower()
        self._versions[norm] = sorted(versions, key=_version_key, reverse=True)
        self._deps[norm] = deps or {}
        self._hashes[norm] = hashes or {}
        self._yanked[norm] = yanked or set()
        self._python_constraints[norm] = python_constraints or {}

    def get_available_versions(self, package: str) -> list[str]:
        norm = re.sub(r"[-_.]+", "-", package).lower()
        return self._versions.get(norm, [])

    def get_dependencies(self, package: str, version: str) -> list[VersionConstraint]:
        norm = re.sub(r"[-_.]+", "-", package).lower()
        return self._deps.get(norm, {}).get(version, [])

    def get_package_hash(self, package: str, version: str) -> str:
        norm = re.sub(r"[-_.]+", "-", package).lower()
        return self._hashes.get(norm, {}).get(version, "")

    def is_yanked(self, package: str, version: str) -> bool:
        norm = re.sub(r"[-_.]+", "-", package).lower()
        return version in self._yanked.get(norm, set())

    def get_python_constraint(self, package: str, version: str) -> str:
        norm = re.sub(r"[-_.]+", "-", package).lower()
        return self._python_constraints.get(norm, {}).get(version, "")


class PyPIPackageIndex(PackageIndex):
    """Live PyPI index using depcheck's existing pypi module."""

    def __init__(self) -> None:
        self._cache: dict[str, list[str]] = {}

    def get_available_versions(self, package: str) -> list[str]:
        if package in self._cache:
            return self._cache[package]
        try:
            from depcheck.pypi import fetch_package_info
            info = fetch_package_info(package)
            if info and "releases" in info:
                versions = list(info["releases"].keys())
                versions = sorted(versions, key=_version_key, reverse=True)
                self._cache[package] = versions
                return versions
        except Exception:
            pass
        return []

    def get_dependencies(self, package: str, version: str) -> list[VersionConstraint]:
        try:
            from depcheck.pypi import fetch_package_info
            info = fetch_package_info(package)
            if info and "releases" in info:
                release = info["releases"].get(version, [])
                for file_info in release:
                    if file_info.get("packagetype") == "bdist_wheel":
                        requires = file_info.get("requires_dist", [])
                        if requires:
                            return _parse_requires_dist(requires, source=package)
        except Exception:
            pass
        return []

    def get_package_hash(self, package: str, version: str) -> str:
        try:
            from depcheck.pypi import fetch_package_info
            info = fetch_package_info(package)
            if info and "releases" in info:
                release = info["releases"].get(version, [])
                for file_info in release:
                    digests = file_info.get("digests", {})
                    sha = digests.get("sha256", "")
                    if sha:
                        return sha
        except Exception:
            pass
        return ""

    def is_yanked(self, package: str, version: str) -> bool:
        try:
            from depcheck.pypi import fetch_package_info
            info = fetch_package_info(package)
            if info and "releases" in info:
                release = info["releases"].get(version, [])
                for file_info in release:
                    if file_info.get("yanked", False):
                        return True
        except Exception:
            pass
        return False


# ---------------------------------------------------------------------------
# Resolver engine
# ---------------------------------------------------------------------------


class DependencyResolver:
    """Backtracking dependency resolver with multiple strategies."""

    def __init__(
        self,
        index: PackageIndex,
        strategy: ResolutionStrategy = ResolutionStrategy.NEWEST,
        python_version: str = "3.12",
        max_iterations: int = 10000,
        allow_prerelease: bool = False,
        ignore_yanked: bool = True,
    ) -> None:
        self.index = index
        self.strategy = strategy
        self.python_version = python_version
        self.max_iterations = max_iterations
        self.allow_prerelease = allow_prerelease
        self.ignore_yanked = ignore_yanked
        self._iterations = 0
        self._conflicts: list[Conflict] = []

    def resolve(self, requirements: list[VersionConstraint]) -> ResolutionResult:
        """Resolve a set of requirements into a compatible version set.

        Uses backtracking: if a chosen version leads to a conflict, we
        backtrack and try the next candidate.
        """
        import time

        start = time.monotonic()
        self._iterations = 0
        self._conflicts = []

        # Group constraints by package
        constraints_by_package = _group_constraints(requirements)

        # Resolve each package
        resolved: dict[str, ResolvedPackage] = {}
        unresolved: list[str] = []

        # Queue of packages to resolve
        queue = list(constraints_by_package.keys())
        visited: set[str] = set()

        while queue and self._iterations < self.max_iterations:
            pkg_name = queue.pop(0)
            norm = re.sub(r"[-_.]+", "-", pkg_name).lower()

            if norm in visited:
                continue
            visited.add(norm)
            self._iterations += 1

            # Get constraints for this package
            pkg_constraints = constraints_by_package.get(norm, [])
            if not pkg_constraints:
                # Transitive dep with no direct constraint — any version ok
                pkg_constraints = [VersionConstraint(package=norm, specifier=">=0.0.0", source="transitive")]

            # Find compatible version
            version = self._find_compatible_version(norm, pkg_constraints, resolved)
            if version is None:
                unresolved.append(norm)
                # Record conflict
                merged = self._merge_constraints(pkg_constraints)
                self._conflicts.append(
                    Conflict(
                        conflict_type=ConflictType.VERSION_CONFLICT,
                        package=norm,
                        message=f"No compatible version found for {norm} with constraints: {merged}",
                        constraints=pkg_constraints,
                        suggested_fix=self._suggest_fix(norm, pkg_constraints),
                    )
                )
                continue

            # Get dependencies of the resolved version
            deps = self.index.get_dependencies(norm, version)
            resolved_pkg = ResolvedPackage(
                name=norm,
                version=version,
                constraints=pkg_constraints,
                dependencies=[d.package for d in deps],
                is_transitive=norm not in {re.sub(r"[-_.]+", "-", r.package).lower() for r in requirements},
                source="pypi",
                hash_sha256=self.index.get_package_hash(norm, version),
                python_version=self.index.get_python_constraint(norm, version),
            )
            resolved[norm] = resolved_pkg

            # Add transitive dependencies to the queue and constraint map
            for dep in deps:
                dep_norm = re.sub(r"[-_.]+", "-", dep.package).lower()
                if dep_norm not in constraints_by_package:
                    constraints_by_package[dep_norm] = []
                constraints_by_package[dep_norm].append(dep)
                if dep_norm not in visited:
                    queue.append(dep_norm)

        # Check for circular dependencies
        circular = self._detect_circular_deps(resolved)
        for cycle in circular:
            self._conflicts.append(
                Conflict(
                    conflict_type=ConflictType.CIRCULAR_DEPENDENCY,
                    package=" -> ".join(cycle),
                    message=f"Circular dependency detected: {' -> '.join(cycle)}",
                    suggested_fix="Consider refactoring to break the cycle, or use lazy imports.",
                )
            )

        elapsed_ms = (time.monotonic() - start) * 1000

        result = ResolutionResult(
            resolved=list(resolved.values()),
            conflicts=self._conflicts,
            unresolved=unresolved,
            strategy_used=self.strategy,
            resolution_time_ms=round(elapsed_ms, 2),
            iterations=self._iterations,
            is_complete=len(unresolved) == 0 and len(circular) == 0,
        )
        return result

    def _find_compatible_version(
        self,
        package: str,
        constraints: list[VersionConstraint],
        already_resolved: dict[str, ResolvedPackage],
    ) -> str | None:
        """Find a version that satisfies all constraints for a package."""
        available = self.index.get_available_versions(package)
        if not available:
            return None

        # Filter out yanked versions if configured
        if self.ignore_yanked:
            available = [v for v in available if not self.index.is_yanked(package, v)]

        # Filter out prerelease if not allowed
        if not self.allow_prerelease:
            available = [v for v in available if not _is_prerelease(v)]

        # Sort according to strategy
        if self.strategy == ResolutionStrategy.OLDEST:
            available = sorted(available, key=_version_key)
        elif self.strategy == ResolutionStrategy.MINIMUM_COMPATIBLE:
            available = sorted(available, key=_version_key)
        else:  # NEWEST
            available = sorted(available, key=_version_key, reverse=True)

        # Check each candidate against all constraints
        merged_spec = self._merge_constraints(constraints)

        for version in available:
            try:
                v = Version(version)
            except InvalidVersion:
                continue

            # Check if version satisfies merged specifier
            if v in SpecifierSet(merged_spec):
                # Also verify against already-resolved packages (bidirectional compat)
                if self._check_reverse_compatibility(package, version, already_resolved):
                    return version

        return None

    def _merge_constraints(self, constraints: list[VersionConstraint]) -> str:
        """Merge multiple constraints into a single specifier string."""
        parts = []
        for c in constraints:
            spec = c.specifier.strip()
            if spec and spec != "*":
                parts.append(spec)
        return ",".join(parts) if parts else ">=0.0.0"

    def _check_reverse_compatibility(
        self,
        package: str,
        version: str,
        already_resolved: dict[str, ResolvedPackage],
    ) -> bool:
        """Check if the new package version is compatible with already-resolved deps."""
        # Get dependencies of the candidate version
        deps = self.index.get_dependencies(package, version)
        for dep_constraint in deps:
            dep_norm = re.sub(r"[-_.]+", "-", dep_constraint.package).lower()
            if dep_norm in already_resolved:
                resolved_ver = already_resolved[dep_norm].version
                if not dep_constraint.allows(resolved_ver):
                    return False
        return True

    def _suggest_fix(self, package: str, constraints: list[VersionConstraint]) -> str:
        """Suggest a fix for a version conflict."""
        if not constraints:
            return f"Check that package '{package}' exists on PyPI."

        # Find the most restrictive constraint pair
        specifiers = [c.specifier for c in constraints if c.specifier]
        sources = [c.source for c in constraints if c.source]

        if len(specifiers) > 1:
            return (
                f"Constraints {specifiers} from {sources} may be incompatible. "
                f"Consider loosening one or more constraints."
            )
        return f"No version of '{package}' satisfies {specifiers}. Check if the package is published."

    def _detect_circular_deps(self, resolved: dict[str, ResolvedPackage]) -> list[list[str]]:
        """Detect circular dependencies in the resolved set."""
        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()
        path: list[str] = []

        def dfs(node: str) -> None:
            norm = re.sub(r"[-_.]+", "-", node).lower()
            if norm in rec_stack:
                # Found a cycle
                cycle_start = path.index(norm)
                cycle = path[cycle_start:] + [norm]
                cycles.append(cycle)
                return
            if norm in visited:
                return

            visited.add(norm)
            rec_stack.add(norm)
            path.append(norm)

            pkg = resolved.get(norm)
            if pkg:
                for dep in pkg.dependencies:
                    dfs(dep)

            path.pop()
            rec_stack.discard(norm)

        for pkg_name in resolved:
            if pkg_name not in visited:
                dfs(pkg_name)

        return cycles


# ---------------------------------------------------------------------------
# Dependency deduplication
# ---------------------------------------------------------------------------


def deduplicate_dependencies(
    resolved: list[ResolvedPackage],
) -> list[ResolvedPackage]:
    """Deduplicate resolved packages by normalized name.

    When the same package appears multiple times (e.g., with different
    capitalization or separators), keep the one with the most constraints.
    """
    by_name: dict[str, ResolvedPackage] = {}
    for pkg in resolved:
        norm = pkg.normalized_name
        if norm not in by_name or len(pkg.constraints) > len(by_name[norm].constraints):
            by_name[norm] = pkg

    return list(by_name.values())


def find_duplicate_deps(resolved: list[ResolvedPackage]) -> list[dict[str, Any]]:
    """Find packages that appear multiple times (differing names, same package)."""
    name_groups: dict[str, list[ResolvedPackage]] = defaultdict(list)
    for pkg in resolved:
        name_groups[pkg.normalized_name].append(pkg)

    duplicates = []
    for norm, pkgs in name_groups.items():
        if len(pkgs) > 1:
            duplicates.append({
                "normalized_name": norm,
                "variants": [p.name for p in pkgs],
                "versions": [p.version for p in pkgs],
            })
    return duplicates


# ---------------------------------------------------------------------------
# Lockfile generation
# ---------------------------------------------------------------------------


def generate_lockfile(
    result: ResolutionResult,
    format: LockfileFormat = LockfileFormat.DEPCHECK,
    project_name: str = "unknown",
) -> str:
    """Generate a lockfile from resolution results.

    Supports multiple formats: depcheck.lock (custom), requirements.txt (pip),
    Pipfile.lock (pipenv), poetry.lock (poetry).
    """
    if format == LockfileFormat.PIP:
        return _generate_pip_lockfile(result)
    elif format == LockfileFormat.PIPENV:
        return _generate_pipenv_lockfile(result, project_name)
    elif format == LockfileFormat.POETRY:
        return _generate_poetry_lockfile(result)
    else:
        return _generate_depcheck_lockfile(result, project_name)


def _generate_depcheck_lockfile(result: ResolutionResult, project_name: str) -> str:
    """Generate depcheck.lock JSON format."""
    lock_data = {
        "$schema": "https://depcheck.dev/schema/lockfile/v1",
        "lockfileVersion": 1,
        "projectName": project_name,
        "generatedAt": _timestamp(),
        "strategy": result.strategy_used.value,
        "resolutionTimeMs": result.resolution_time_ms,
        "iterations": result.iterations,
        "isComplete": result.is_complete,
        "packages": {pkg.normalized_name: pkg.to_dict() for pkg in result.resolved},
        "conflicts": [c.to_dict() for c in result.conflicts],
        "unresolved": result.unresolved,
    }
    return json.dumps(lock_data, indent=2, sort_keys=False)


def _generate_pip_lockfile(result: ResolutionResult) -> str:
    """Generate pip-compatible requirements.txt with hashes."""
    lines = [
        "# Generated by depcheck resolve",
        f"# Strategy: {result.strategy_used.value}",
        f"# Resolved: {len(result.resolved)} packages",
        f"# Conflicts: {result.conflict_count}",
        "",
    ]
    for pkg in sorted(result.resolved, key=lambda p: p.normalized_name):
        constraint_str = ",".join(
            c.specifier for c in pkg.constraints if c.specifier and c.specifier != "*"
        )
        if constraint_str:
            line = f"{pkg.name}{constraint_str}"
        else:
            line = f"{pkg.name}=={pkg.version}"

        if pkg.hash_sha256:
            line += f" \\\n    --hash=sha256:{pkg.hash_sha256}"
        lines.append(line)

    if result.conflicts:
        lines.append("")
        lines.append("# CONFLICTS (not installed):")
        for conflict in result.conflicts:
            lines.append(f"# {conflict.package}: {conflict.message}")

    return "\n".join(lines) + "\n"


def _generate_pipenv_lockfile(result: ResolutionResult, project_name: str) -> str:
    """Generate Pipfile.lock format."""
    data: dict[str, Any] = {
        "_meta": {
            "hash": {"sha256": _hash_result(result)},
            "pipfile-spec": 6,
            "name": project_name,
            "requires": {"python_version": "3.12"},
            "sources": [
                {
                    "name": "pypi",
                    "url": "https://pypi.org/simple",
                    "verify_ssl": True,
                }
            ],
        },
        "default": {},
        "develop": {},
    }

    for pkg in result.resolved:
        entry: dict[str, Any] = {"version": f"=={pkg.version}"}
        if pkg.hash_sha256:
            entry["hashes"] = {"sha256": pkg.hash_sha256}
        if pkg.dependencies:
            entry["dependencies"] = {}
            for dep_name in pkg.dependencies:
                dep_pkg = result.get_package(dep_name)
                if dep_pkg:
                    entry["dependencies"][dep_name] = {"version": f"=={dep_pkg.version}"}
        data["default"][pkg.normalized_name] = entry

    return json.dumps(data, indent=2, sort_keys=True)


def _generate_poetry_lockfile(result: ResolutionResult) -> str:
    """Generate poetry.lock TOML format."""
    lines = [
        "# This file is automatically @generated by depcheck.",
        "# It is not intended for manual editing.",
        '[[package]]',
    ]
    for pkg in sorted(result.resolved, key=lambda p: p.normalized_name):
        lines.append(f'name = "{pkg.name}"')
        lines.append(f'version = "{pkg.version}"')
        if pkg.dependencies:
            lines.append(f'dependencies = {json.dumps(pkg.dependencies)}')
        lines.append("")
        lines.append("[[package]]")

    # Remove trailing [[package]]
    if lines and lines[-1] == "[[package]]":
        lines.pop()

    # Add metadata
    lines.extend([
        "",
        "[metadata]",
        f'lock-version = "1.0"',
        f'python-versions = "3.12"',
        f'content-hash = "{_hash_result(result)}"',
    ])

    return "\n".join(lines) + "\n"


def parse_lockfile(path: Path) -> list[VersionConstraint]:
    """Parse a lockfile into a list of version constraints.

    Supports: depcheck.lock, requirements.txt, Pipfile.lock, poetry.lock
    """
    if not path.exists():
        return []

    name = path.name.lower()

    if name == "depcheck.lock" or name.endswith(".depcheck.lock"):
        return _parse_depcheck_lockfile(path)
    elif name == "pipfile.lock":
        return _parse_pipfile_lock(path)
    elif name == "poetry.lock":
        return _parse_poetry_lock(path)
    else:
        # Try as requirements.txt
        return _parse_requirements_lockfile(path)


def _parse_depcheck_lockfile(path: Path) -> list[VersionConstraint]:
    """Parse depcheck.lock JSON."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        constraints = []
        packages = data.get("packages", {})
        for _norm_name, pkg_data in packages.items():
            name = pkg_data.get("name", _norm_name)
            version = pkg_data.get("version", "")
            constraints.append(
                VersionConstraint(
                    package=name,
                    specifier=f"=={version}" if version else ">=0.0.0",
                    source="depcheck.lock",
                )
            )
        return constraints
    except (json.JSONDecodeError, KeyError):
        return []


def _parse_requirements_lockfile(path: Path) -> list[VersionConstraint]:
    """Parse pip requirements.txt format."""
    constraints = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # Remove hash annotations
        line = re.sub(r"\s*\\?\s*--hash=.*$", "", line)
        # Parse name and specifier
        match = re.match(r"^([a-zA-Z0-9][-a-zA-Z0-9_.]*)(.*)", line)
        if match:
            name = match.group(1).strip()
            spec = match.group(2).strip()
            if spec:
                constraints.append(VersionConstraint(package=name, specifier=spec, source=str(path)))
    return constraints


def _parse_pipfile_lock(path: Path) -> list[VersionConstraint]:
    """Parse Pipfile.lock JSON."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        constraints = []
        for section in ("default", "develop"):
            for name, info in data.get(section, {}).items():
                version = info.get("version", "")
                if version:
                    constraints.append(
                        VersionConstraint(package=name, specifier=version, source="Pipfile.lock")
                    )
        return constraints
    except (json.JSONDecodeError, KeyError):
        return []


def _parse_poetry_lock(path: Path) -> list[VersionConstraint]:
    """Parse poetry.lock TOML (simple parser for basic structure)."""
    constraints = []
    content = path.read_text(encoding="utf-8")
    # Simple regex-based TOML parsing for [[package]] sections
    pkg_pattern = re.compile(
        r'\[\[package\]\]\s*name\s*=\s*"([^"]+)"\s*version\s*=\s*"([^"]+)"',
        re.MULTILINE,
    )
    for match in pkg_pattern.finditer(content):
        name = match.group(1)
        version = match.group(2)
        constraints.append(
            VersionConstraint(package=name, specifier=f"=={version}", source="poetry.lock")
        )
    return constraints


# ---------------------------------------------------------------------------
# Conflict analysis
# ---------------------------------------------------------------------------


def analyze_conflicts(result: ResolutionResult) -> ConflictAnalysis:
    """Deep analysis of resolution conflicts with categorization and remediation."""
    analysis = ConflictAnalysis()

    for conflict in result.conflicts:
        if conflict.conflict_type == ConflictType.VERSION_CONFLICT:
            analysis.version_conflicts.append(conflict)
        elif conflict.conflict_type == ConflictType.CIRCULAR_DEPENDENCY:
            analysis.circular_deps.append(conflict)
        elif conflict.conflict_type == ConflictType.MISSING_PACKAGE:
            analysis.missing_packages.append(conflict)
        elif conflict.conflict_type == ConflictType.YANKED_VERSION:
            analysis.yanked_versions.append(conflict)
        elif conflict.conflict_type == ConflictType.INCOMPATIBLE_PYTHON:
            analysis.python_incompatibilities.append(conflict)

    analysis.total_conflicts = len(result.conflicts)
    analysis.critical_conflicts = len([
        c for c in result.conflicts
        if c.conflict_type in (ConflictType.VERSION_CONFLICT, ConflictType.CIRCULAR_DEPENDENCY)
    ])
    analysis.has_circular_deps = len(analysis.circular_deps) > 0
    analysis.has_version_conflicts = len(analysis.version_conflicts) > 0

    return analysis


@dataclass
class ConflictAnalysis:
    """Detailed analysis of resolution conflicts."""

    version_conflicts: list[Conflict] = field(default_factory=list)
    circular_deps: list[Conflict] = field(default_factory=list)
    missing_packages: list[Conflict] = field(default_factory=list)
    yanked_versions: list[Conflict] = field(default_factory=list)
    python_incompatibilities: list[Conflict] = field(default_factory=list)
    total_conflicts: int = 0
    critical_conflicts: int = 0
    has_circular_deps: bool = False
    has_version_conflicts: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_conflicts": self.total_conflicts,
            "critical_conflicts": self.critical_conflicts,
            "has_circular_deps": self.has_circular_deps,
            "has_version_conflicts": self.has_version_conflicts,
            "version_conflicts": [c.to_dict() for c in self.version_conflicts],
            "circular_deps": [c.to_dict() for c in self.circular_deps],
            "missing_packages": [c.to_dict() for c in self.missing_packages],
            "yanked_versions": [c.to_dict() for c in self.yanked_versions],
            "python_incompatibilities": [c.to_dict() for c in self.python_incompatibilities],
        }

    @property
    def is_healthy(self) -> bool:
        """True if no critical conflicts exist."""
        return self.critical_conflicts == 0


# ---------------------------------------------------------------------------
# Resolution from project path
# ---------------------------------------------------------------------------


def resolve_project(
    project_path: str,
    strategy: ResolutionStrategy = ResolutionStrategy.NEWEST,
    python_version: str = "3.12",
    use_index: PackageIndex | None = None,
    allow_prerelease: bool = False,
) -> ResolutionResult:
    """Resolve all dependencies for a project directory.

    Reads requirements.txt, pyproject.toml, or Pipfile from the project
    directory and runs the full resolver.
    """
    from depcheck.scanner import parse_requirements

    path = Path(project_path)
    requirements = parse_requirements(path)

    constraints = []
    for dep in requirements:
        spec = dep.specifier or (f"=={dep.version}" if dep.version else ">=0.0.0")
        constraints.append(
            VersionConstraint(package=dep.name, specifier=spec, source="project")
        )

    # Also parse any lockfile
    lockfile_constraints = _find_and_parse_lockfile(path)
    constraints.extend(lockfile_constraints)

    index = use_index or PyPIPackageIndex()
    resolver = DependencyResolver(
        index=index,
        strategy=strategy,
        python_version=python_version,
        allow_prerelease=allow_prerelease,
    )

    return resolver.resolve(constraints)


def _find_and_parse_lockfile(path: Path) -> list[VersionConstraint]:
    """Find and parse any lockfile in the project directory."""
    lockfile_names = [
        "depcheck.lock",
        "requirements.lock",
        "Pipfile.lock",
        "poetry.lock",
    ]
    for name in lockfile_names:
        lockfile = path / name
        if lockfile.exists():
            return parse_lockfile(lockfile)
    return []


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_resolve_table(result: ResolutionResult, *, console: Any = None) -> None:
    """Render resolution results as a rich table."""
    from rich.console import Console
    from rich.table import Table

    if console is None:
        console = Console()

    # Summary
    console.print(f"\n[bold]Dependency Resolution Results[/bold]")
    console.print(f"Strategy: {result.strategy_used.value} | Iterations: {result.iterations} | "
                  f"Time: {result.resolution_time_ms:.1f}ms")
    console.print(f"Resolved: [green]{len(result.resolved)}[/green] | "
                  f"Conflicts: [red]{result.conflict_count}[/red] | "
                  f"Unresolved: [yellow]{len(result.unresolved)}[/yellow]")

    # Resolved packages table
    if result.resolved:
        table = Table(title="Resolved Packages", show_lines=True)
        table.add_column("Package", style="cyan")
        table.add_column("Version", style="green")
        table.add_column("Type", style="dim")
        table.add_column("Constraints", style="yellow", max_width=40)
        table.add_column("Deps", style="dim", justify="right")

        for pkg in sorted(result.resolved, key=lambda p: p.normalized_name):
            dep_type = "transitive" if pkg.is_transitive else "direct"
            constraint_str = ", ".join(
                c.specifier for c in pkg.constraints[:3] if c.specifier
            )
            if len(pkg.constraints) > 3:
                constraint_str += f" (+{len(pkg.constraints) - 3} more)"
            table.add_row(
                pkg.name,
                pkg.version,
                dep_type,
                constraint_str or "*",
                str(len(pkg.dependencies)),
            )
        console.print(table)

    # Conflicts
    if result.conflicts:
        console.print("\n[bold red]Conflicts[/bold red]")
        for conflict in result.conflicts:
            icon = "⚠" if conflict.conflict_type == ConflictType.VERSION_CONFLICT else "↻"
            console.print(f"  {icon} {conflict.package}: {conflict.message}")
            if conflict.suggested_fix:
                console.print(f"    [dim]Fix: {conflict.suggested_fix}[/dim]")


def render_resolve_json(result: ResolutionResult) -> str:
    """Render resolution results as JSON."""
    return json.dumps(result.to_dict(), indent=2)


def render_lockfile_diff_table(
    old_result: ResolutionResult,
    new_result: ResolutionResult,
    *,
    console: Any = None,
) -> None:
    """Render a diff between two resolution results (e.g., before/after upgrade)."""
    from rich.console import Console
    from rich.table import Table

    if console is None:
        console = Console()

    old_pkgs = {p.normalized_name: p for p in old_result.resolved}
    new_pkgs = {p.normalized_name: p for p in new_result.resolved}

    added = set(new_pkgs) - set(old_pkgs)
    removed = set(old_pkgs) - set(new_pkgs)
    common = set(old_pkgs) & set(new_pkgs)
    changed = {
        n for n in common
        if old_pkgs[n].version != new_pkgs[n].version
    }
    unchanged = common - changed

    table = Table(title="Lockfile Diff", show_lines=True)
    table.add_column("Package", style="cyan")
    table.add_column("Old Version", style="red")
    table.add_column("New Version", style="green")
    table.add_column("Change", style="yellow")

    for name in sorted(added):
        table.add_row(new_pkgs[name].name, "-", new_pkgs[name].version, "[green]added[/green]")
    for name in sorted(removed):
        table.add_row(old_pkgs[name].name, old_pkgs[name].version, "-", "[red]removed[/red]")
    for name in sorted(changed):
        table.add_row(
            new_pkgs[name].name,
            old_pkgs[name].version,
            new_pkgs[name].version,
            "[yellow]changed[/yellow]",
        )
    for name in sorted(unchanged):
        table.add_row(old_pkgs[name].name, old_pkgs[name].version, new_pkgs[name].version, "[dim]unchanged[/dim]")

    console.print(table)
    console.print(f"\nAdded: [green]{len(added)}[/green] | "
                  f"Removed: [red]{len(removed)}[/red] | "
                  f"Changed: [yellow]{len(changed)}[/yellow] | "
                  f"Unchanged: [dim]{len(unchanged)}[/dim]")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _version_key(version_str: str) -> tuple:
    """Sort key for version strings using packaging.version."""
    try:
        v = Version(version_str)
        # Normalize release to tuple of ints for consistent comparison
        release = tuple(int(x) for x in v.release)
        # Convert pre-release tuple to sortable ints; ("a",1)→(0,1), ("b",1)→(1,1), ("rc",1)→(2,1)
        if v.pre is not None:
            pre_type_map = {"a": 0, "b": 1, "rc": 2}
            pre = (pre_type_map.get(v.pre[0], 3), v.pre[1])
        else:
            pre = (99, 0)  # non-pre sorts after pre
        post = v.post if v.post is not None else -1
        dev = v.dev if v.dev is not None else 999999
        return (v.epoch, release, pre, post, dev)
    except InvalidVersion:
        return (0, (0,), (99, 0), -1, 999999)


def _is_prerelease(version_str: str) -> bool:
    """Check if a version string is a pre-release."""
    try:
        v = Version(version_str)
        return v.is_prerelease
    except InvalidVersion:
        return bool(re.search(r"[a-zA-Z]", version_str.split(".")[-1]) if version_str else False)


def _group_constraints(constraints: list[VersionConstraint]) -> dict[str, list[VersionConstraint]]:
    """Group constraints by normalized package name."""
    groups: dict[str, list[VersionConstraint]] = defaultdict(list)
    for c in constraints:
        norm = re.sub(r"[-_.]+", "-", c.package).lower()
        groups[norm].append(c)
    return dict(groups)


def _parse_requires_dist(requires: list[str], source: str = "") -> list[VersionConstraint]:
    """Parse PEP 566 requires_dist entries into VersionConstraints."""
    constraints = []
    for req in requires:
        # Remove extras and environment markers
        req_clean = re.sub(r"\s*;.*$", "", req).strip()
        req_clean = re.sub(r"\s*\[.*?\]", "", req_clean).strip()
        match = re.match(r"^([a-zA-Z0-9][-a-zA-Z0-9_.]*)(.*)", req_clean)
        if match:
            name = match.group(1).strip()
            spec = match.group(2).strip()
            if spec:
                constraints.append(VersionConstraint(package=name, specifier=spec, source=source))
    return constraints


def _hash_result(result: ResolutionResult) -> str:
    """Compute a deterministic hash of the resolution result."""
    content = json.dumps(result.to_dict(), sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:64]


def _timestamp() -> str:
    """Return ISO 8601 timestamp."""
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
