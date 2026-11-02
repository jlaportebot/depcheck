"""Core scanning logic for depcheck."""

from __future__ import annotations

import datetime
import re
from pathlib import Path
from typing import Any

from depcheck.cache import OfflineCacheMissError
from depcheck.licenses import LicenseCategory, check_license_compliance, parse_license_from_pypi
from depcheck.models import (
    HealthStatus,
    LicenseInfo,
    PackageReport,
    ParsedDependency,
    ScanResult,
    Vulnerability,
)
from depcheck.naming import normalize_package_name
from depcheck.osv import OSVClient
from depcheck.pypi import PyPIClient
from depcheck.toml import loads_toml

# Threshold for unmaintained detection (1 year)
UNMAINTAINED_THRESHOLD_DAYS = 365

# Patterns for parsing requirements.txt
REQUIREMENTS_LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z0-9][a-zA-Z0-9._-]*)"
    r"(?P<specifier>[><=!~]+\s*(?P<version>[0-9][0-9.a-zA-Z*+-]*))?"
)


def parse_requirements_txt(filepath: Path) -> list[ParsedDependency]:
    """Parse a requirements.txt file into a list of dependencies.

    Handles:
    - Plain package names (e.g., "requests")
    - Pinned versions (e.g., "requests==2.31.0")
    - Version specifiers (e.g., "requests>=2.28")
    - Comments and blank lines (skipped)
    - Line continuations (skipped for simplicity)
    - Options like -i, --index-url (skipped)

    Args:
        filepath: Path to the requirements.txt file.

    Returns:
        List of ParsedDependency objects.
    """
    dependencies: list[ParsedDependency] = []

    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return dependencies

    for line in content.splitlines():
        line = line.strip()

        # Skip empty lines, comments, and pip options
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        match = REQUIREMENTS_LINE_RE.match(line)
        if match:
            name = normalize_package_name(match.group("name"))
            version = match.group("version") or None
            specifier = match.group("specifier") or None
            dependencies.append(ParsedDependency(name=name, version=version, specifier=specifier))

    return dependencies


def parse_pyproject_toml(filepath: Path) -> list[ParsedDependency]:
    """Parse a pyproject.toml file for dependencies.

    Supports both [project.dependencies] and [tool.poetry.dependencies].

    Args:
        filepath: Path to the pyproject.toml file.

    Returns:
        List of ParsedDependency objects.
    """
    dependencies: list[ParsedDependency] = []

    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return dependencies

    try:
        data = loads_toml(content, path=str(filepath))
    except Exception:
        return dependencies

    # PEP 621 format: [project.dependencies]
    project_deps = data.get("project", {}).get("dependencies", [])
    for dep_str in project_deps:
        parsed = _parse_pep621_dependency(dep_str)
        if parsed:
            dependencies.append(parsed)

    # Poetry format: [tool.poetry.dependencies]
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, version_spec in poetry_deps.items():
        if name.lower() == "python":
            continue
        version = None
        if isinstance(version_spec, str) and version_spec != "*":
            # Strip version specifier operators for simple cases
            clean = re.sub(r"^[><=!~]+\s*", "", version_spec)
            if clean and clean[0].isdigit():
                version = clean
        elif isinstance(version_spec, dict):
            version = version_spec.get("version")
            if version:
                clean = re.sub(r"^[><=!~]+\s*", "", version)
                if clean and clean[0].isdigit():
                    version = clean
        dependencies.append(ParsedDependency(name=normalize_package_name(name), version=version))

    return dependencies


def _parse_pep621_dependency(dep_str: str) -> ParsedDependency | None:
    """Parse a PEP 621 dependency string like 'requests>=2.28' or 'requests==2.31.0'.

    Args:
        dep_str: The dependency string.

    Returns:
        A ParsedDependency, or None if parsing fails.
    """
    # Handle extras like "requests[security]>=2.28"
    dep_str = dep_str.strip()
    match = re.match(
        r"^(?P<name>[a-zA-Z0-9][a-zA-Z0-9._-]*)"
        r"(\[(?P<extras>[^\]]+)\])?"
        r"(?P<specifier>[><=!~].+)?$",
        dep_str,
    )
    if not match:
        return None

    name = normalize_package_name(match.group("name"))
    specifier = match.group("specifier")
    version = None

    if specifier:
        # Try to extract exact version from == specifier
        exact_match = re.match(r"==\s*([0-9][0-9.a-zA-Z*+-]*)", specifier)
        if exact_match:
            version = exact_match.group(1)

    return ParsedDependency(name=name, version=version, specifier=specifier)


def parse_pipfile(filepath: Path) -> list[ParsedDependency]:
    """Parse a Pipfile for dependencies.

    Uses proper TOML parsing (via depcheck.toml) instead of regex-based line parsing.

    Args:
        filepath: Path to the Pipfile.

    Returns:
        List of ParsedDependency objects.
    """
    dependencies: list[ParsedDependency] = []

    try:
        content = filepath.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return dependencies

    try:
        data = loads_toml(content, path=str(filepath))
    except Exception:
        return dependencies

    packages = data.get("packages", {})
    for name, version_spec in packages.items():
        version = None
        specifier = None
        if isinstance(version_spec, str):
            if version_spec == "*":
                version = None
            elif version_spec.startswith("=="):
                # Exact pin like "==2.31.0"
                version = version_spec[2:]
                specifier = version_spec
            else:
                # Other specifiers like ">=8.0", "^2.28"
                specifier = version_spec
                # Try to extract a version number for display
                clean = re.sub(r"^[><=!~^]+\s*", "", version_spec)
                if clean and clean[0].isdigit():
                    version = clean
        elif isinstance(version_spec, dict):
            # Pipfile can use dict format: {version = "==2.31.0", extras = [...]}
            v = version_spec.get("version", "")
            if isinstance(v, str):
                if v.startswith("=="):
                    version = v[2:]
                    specifier = v
                elif v and v != "*":
                    specifier = v
                    clean = re.sub(r"^[><=!~^]+\s*", "", v)
                    if clean and clean[0].isdigit():
                        version = clean

        dependencies.append(
            ParsedDependency(
                name=normalize_package_name(name),
                version=version,
                specifier=specifier,
            )
        )

    return dependencies


def discover_dependencies(project_path: Path) -> tuple[list[ParsedDependency], list[str]]:
    """Discover dependencies from a project directory.

    Looks for requirements.txt, pyproject.toml, and Pipfile.

    Args:
        project_path: Path to the project directory.

    Returns:
        Tuple of (list of dependencies, list of files scanned).
    """
    all_deps: list[ParsedDependency] = []
    files_scanned: list[str] = []

    # Check for requirements.txt
    req_file = project_path / "requirements.txt"
    if req_file.is_file():
        deps = parse_requirements_txt(req_file)
        all_deps.extend(deps)
        files_scanned.append(str(req_file))

    # Check for pyproject.toml
    pyproject_file = project_path / "pyproject.toml"
    if pyproject_file.is_file():
        deps = parse_pyproject_toml(pyproject_file)
        all_deps.extend(deps)
        files_scanned.append(str(pyproject_file))

    # Check for Pipfile
    pipfile = project_path / "Pipfile"
    if pipfile.is_file():
        deps = parse_pipfile(pipfile)
        all_deps.extend(deps)
        files_scanned.append(str(pipfile))

    # Deduplicate by package name (first occurrence wins)
    seen: set[str] = set()
    unique_deps: list[ParsedDependency] = []
    for dep in all_deps:
        if dep.name not in seen:
            seen.add(dep.name)
            unique_deps.append(dep)

    return unique_deps, files_scanned


def build_package_report(
    dep: ParsedDependency,
    info: dict[str, Any] | None,
    pypi_client: PyPIClient,
    *,
    vulnerabilities: list[Vulnerability] | None = None,
    check_licenses: bool = False,
    allowed_license_categories: list[LicenseCategory] | None = None,
    denied_licenses: list[str] | None = None,
) -> PackageReport:
    """Build a health report from already-fetched package metadata.

    This is the pure half of :func:`check_package_health`: all network access
    has already happened, so the same metadata can be reused for many packages.

    Args:
        dep: The parsed dependency to report on.
        info: The package metadata fetched from PyPI (None when not found).
        pypi_client: PyPI API client, used for version resolution helpers.
        vulnerabilities: Vulnerabilities already fetched for this package.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: List of allowed license categories.
        denied_licenses: List of specific SPDX IDs to deny.

    Returns:
        A PackageReport with health status information.
    """
    report = PackageReport(
        name=dep.name,
        installed_version=dep.version or "unknown",
    )

    if info is None:
        report.status = HealthStatus.REMOVED
        report.is_removed = True
        report.error = "Package not found on PyPI"
        return report

    report.latest_version = info.get("info", {}).get("version")

    resolved_version = pypi_client.resolve_version(dep, info)
    if resolved_version:
        report.installed_version = resolved_version

    if report.installed_version and report.installed_version != "unknown":
        if pypi_client.is_version_yanked(dep.name, report.installed_version, info):
            report.status = HealthStatus.YANKED
            report.is_yanked = True
            return report

    if check_licenses:
        report.license_info = _build_license_info(
            info,
            allowed_license_categories=allowed_license_categories,
            denied_licenses=denied_licenses,
        )

    if vulnerabilities:
        report.vulnerabilities = list(vulnerabilities)
        report.status = HealthStatus.VULNERABLE
        return report

    last_release = pypi_client.get_last_release_date(dep.name, info)
    if last_release:
        report.last_release_date = last_release.strftime("%Y-%m-%d")
        days_since = (datetime.datetime.now(tz=last_release.tzinfo) - last_release).days
        if days_since > UNMAINTAINED_THRESHOLD_DAYS:
            report.status = HealthStatus.UNMAINTAINED
            return report

    if report.is_outdated:
        report.status = HealthStatus.OUTDATED
        return report

    report.status = HealthStatus.HEALTHY
    return report


def _build_license_info(
    info: dict[str, Any],
    *,
    allowed_license_categories: list[LicenseCategory] | None,
    denied_licenses: list[str] | None,
) -> LicenseInfo:
    """Build the license information for a package from its PyPI metadata.

    Args:
        info: The package metadata fetched from PyPI.
        allowed_license_categories: List of allowed license categories.
        denied_licenses: List of specific SPDX IDs to deny.

    Returns:
        The license information for the package.
    """
    license_info = parse_license_from_pypi(info)
    license_info = check_license_compliance(
        license_info,
        allowed_categories=allowed_license_categories,
        denied_licenses=denied_licenses,
    )
    return LicenseInfo(
        spdx_id=license_info.spdx_id,
        raw_license=license_info.raw_license,
        category=license_info.category,  # Already a string
        is_compliant=license_info.is_compliant,
        compliance_note=license_info.compliance_note,
    )


def check_package_health(
    dep: ParsedDependency,
    pypi_client: PyPIClient,
    osv_client: OSVClient,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
    allowed_license_categories: list[LicenseCategory] | None = None,
    denied_licenses: list[str] | None = None,
) -> PackageReport:
    """Check the health of a single package.

    Args:
        dep: The parsed dependency to check.
        pypi_client: PyPI API client.
        osv_client: OSV API client.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: List of allowed license categories
        (e.g., [LicenseCategory.PERMISSIVE]).
        denied_licenses: List of specific SPDX IDs to deny.

    Returns:
        A PackageReport with health status information.
    """
    info = pypi_client.get_package_info(dep.name)
    vulnerabilities: list[Vulnerability] | None = None
    if check_vulnerabilities and info is not None:
        version = pypi_client.resolve_version(dep, info)
        if version:
            vulnerabilities = osv_client.query_vulnerabilities(dep.name, version)

    return build_package_report(
        dep,
        info,
        pypi_client,
        vulnerabilities=vulnerabilities,
        check_licenses=check_licenses,
        allowed_license_categories=allowed_license_categories,
        denied_licenses=denied_licenses,
    )


def scan_project(
    project_path: str | Path,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
    allowed_license_categories: list[LicenseCategory] | None = None,
    denied_licenses: list[str] | None = None,
) -> ScanResult:
    """Scan a Python project for dependency health issues.

    This is the main entry point for scanning. It discovers dependencies,
    checks each one against PyPI and OSV, and returns a comprehensive
    scan result.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to check for vulnerabilities (can be slow).
        check_licenses: Whether to check license compliance.
        allowed_license_categories: List of allowed license categories.
        denied_licenses: List of specific SPDX IDs to deny.

    Returns:
        A ScanResult containing health reports for all dependencies.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return ScanResult(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    # Discover dependencies
    dependencies, files_scanned = discover_dependencies(project_path)

    if not dependencies:
        return ScanResult(
            project_path=str(project_path),
            files_scanned=files_scanned,
            errors=["No dependencies found in the project."],
        )

    if not files_scanned:
        return ScanResult(
            project_path=str(project_path),
            errors=[f"No requirements.txt, pyproject.toml, or Pipfile found in {project_path}"],
        )

    try:
        reports = scan_dependencies(
            dependencies,
            check_vulnerabilities=check_vulnerabilities,
            check_licenses=check_licenses,
            allowed_license_categories=allowed_license_categories,
            denied_licenses=denied_licenses,
        )
    except OfflineCacheMissError as exc:
        return ScanResult(
            project_path=str(project_path),
            files_scanned=files_scanned,
            errors=[str(exc)],
        )

    return ScanResult(
        project_path=str(project_path),
        packages=reports,
        files_scanned=files_scanned,
    )


def scan_dependencies(
    dependencies: list[ParsedDependency],
    *,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
    allowed_license_categories: list[LicenseCategory] | None = None,
    denied_licenses: list[str] | None = None,
    pypi_client: PyPIClient | None = None,
    osv_client: OSVClient | None = None,
) -> list[PackageReport]:
    """Check the health of many dependencies with batched network access.

    PyPI metadata is fetched concurrently and OSV vulnerabilities are fetched
    with the batch endpoint, so the number of HTTP round-trips grows with the
    number of *cache misses* rather than with the number of packages.

    Args:
        dependencies: The dependencies to check.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: List of allowed license categories.
        denied_licenses: List of specific SPDX IDs to deny.
        pypi_client: Optional pre-built PyPI client (a temporary one is used
            when omitted).
        osv_client: Optional pre-built OSV client (a temporary one is used
            when omitted).

    Returns:
        One PackageReport per dependency, in the order they were given.
    """
    if not dependencies:
        return []

    owns_pypi = pypi_client is None
    owns_osv = osv_client is None
    active_pypi = pypi_client or PyPIClient()
    active_osv = osv_client or OSVClient()

    try:
        package_infos = _fetch_package_infos(active_pypi, dependencies)
        versions = _resolve_versions(active_pypi, dependencies, package_infos)
        vulnerabilities = _fetch_vulnerabilities(
            active_osv,
            dependencies,
            versions,
            enabled=check_vulnerabilities,
        )
        return [
            _build_report(
                dep,
                active_pypi,
                package_infos.get(dep.name),
                vulnerabilities.get(dep.name),
                check_vulnerabilities=check_vulnerabilities,
                check_licenses=check_licenses,
                allowed_license_categories=allowed_license_categories,
                denied_licenses=denied_licenses,
            )
            for dep in dependencies
        ]
    finally:
        if owns_pypi:
            active_pypi.close()
        if owns_osv:
            active_osv.close()


def _fetch_package_infos(
    pypi_client: PyPIClient,
    dependencies: list[ParsedDependency],
) -> dict[str, dict[str, Any] | None]:
    """Fetch PyPI metadata for every dependency concurrently.

    Args:
        pypi_client: The PyPI API client.
        dependencies: The dependencies to look up.

    Returns:
        Mapping of package name to its metadata (None when not found).
    """
    names = list(dict.fromkeys(dep.name for dep in dependencies))
    return pypi_client.get_package_info_many(names)


def _resolve_versions(
    pypi_client: PyPIClient,
    dependencies: list[ParsedDependency],
    package_infos: dict[str, dict[str, Any] | None],
) -> dict[str, str]:
    """Resolve the concrete version of every dependency.

    Args:
        pypi_client: The PyPI API client.
        dependencies: The dependencies to resolve.
        package_infos: Mapping of package name to its metadata.

    Returns:
        Mapping of package name to its resolved version.
    """
    resolved: dict[str, str] = {}
    for dep in dependencies:
        info = package_infos.get(dep.name)
        if info is None:
            continue
        version = pypi_client.resolve_version(dep, info)
        if version:
            resolved[dep.name] = version
    return resolved


def _fetch_vulnerabilities(
    osv_client: OSVClient,
    dependencies: list[ParsedDependency],
    versions: dict[str, str],
    *,
    enabled: bool,
) -> dict[str, list[Vulnerability]]:
    """Fetch vulnerabilities for every dependency in one batch.

    Args:
        osv_client: The OSV API client.
        dependencies: The dependencies to look up.
        versions: Mapping of package name to its resolved version.
        enabled: Whether vulnerability checking is enabled.

    Returns:
        Mapping of package name to its vulnerabilities.
    """
    if not enabled:
        return {}

    queries = [
        (dep.name, versions[dep.name])
        for dep in dependencies
        if dep.name in versions and versions[dep.name] != "unknown"
    ]
    if not queries:
        return {}

    batch = osv_client.query_vulnerabilities_batch(queries)
    return {name: vulns for (name, _), vulns in batch.items()}


def _build_report(
    dep: ParsedDependency,
    pypi_client: PyPIClient,
    info: dict[str, Any] | None,
    vulnerabilities: list[Vulnerability] | None,
    *,
    check_vulnerabilities: bool,
    check_licenses: bool,
    allowed_license_categories: list[LicenseCategory] | None,
    denied_licenses: list[str] | None,
) -> PackageReport:
    """Build the report for one dependency, converting failures to UNKNOWN.

    Args:
        dep: The dependency to report on.
        pypi_client: The PyPI API client.
        info: The package metadata fetched from PyPI.
        vulnerabilities: The vulnerabilities fetched for this package.
        check_vulnerabilities: Whether vulnerability checking was enabled.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: List of allowed license categories.
        denied_licenses: List of specific SPDX IDs to deny.

    Returns:
        The PackageReport for the dependency.
    """
    try:
        return build_package_report(
            dep,
            info,
            pypi_client,
            vulnerabilities=vulnerabilities if check_vulnerabilities else None,
            check_licenses=check_licenses,
            allowed_license_categories=allowed_license_categories,
            denied_licenses=denied_licenses,
        )
    except OfflineCacheMissError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        return PackageReport(
            name=dep.name,
            installed_version=dep.version or "unknown",
            status=HealthStatus.UNKNOWN,
            error=str(exc),
        )
