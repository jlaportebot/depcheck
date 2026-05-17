"""Core scanning logic for depcheck."""

from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path

from depcheck.models import HealthStatus, PackageReport, ParsedDependency, ScanResult
from depcheck.osv import OSVClient
from depcheck.pypi import PyPIClient

# Threshold for unmaintained detection (1 year)
UNMAINTAINED_THRESHOLD_DAYS = 365

# Patterns for parsing requirements.txt
REQUIREMENTS_LINE_RE = re.compile(
    r"^(?P<name>[a-zA-Z0-9][a-zA-Z0-9._-]*)"
    r"(?P<specifier>[><=!~]+\s*(?P<version>[0-9][0-9.a-zA-Z*+-]*))?"
)


def normalize_package_name(name: str) -> str:
    """Normalize a Python package name per PEP 503.

    Args:
        name: The raw package name.

    Returns:
        The normalized package name (lowercased, hyphens to dashes).
    """
    return re.sub(r"[-_.]+", "-", name).lower()


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

    # Use tomli for Python < 3.11, tomllib for 3.11+
    if sys.version_info >= (3, 11):
        import tomllib
    else:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return dependencies

    try:
        data = tomllib.loads(content)
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

    Reads the [packages] section of a Pipfile.

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

    # Simple parsing: find [packages] section
    in_packages = False
    for line in content.splitlines():
        stripped = line.strip()

        if stripped == "[packages]":
            in_packages = True
            continue
        elif stripped.startswith("["):
            in_packages = False
            continue

        if not in_packages or not stripped or stripped.startswith("#"):
            continue

        # Parse "package = version" format (supports quoted and unquoted values)
        # Examples: requests = "==2.31.0", flask = "*", click = ">=8.0", numpy = "1.24"
        match = re.match(
            r'^(?P<name>[a-zA-Z0-9][a-zA-Z0-9._-]*)\s*=\s*"?'
            r"(?P<version>[><=!~*0-9][0-9.a-zA-Z*><=!~+-]*)?"
            r'"?\s*$',
            stripped,
        )
        if match:
            name = normalize_package_name(match.group("name"))
            version = match.group("version") or None
            dependencies.append(ParsedDependency(name=name, version=version))

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


def check_package_health(
    dep: ParsedDependency,
    pypi_client: PyPIClient,
    osv_client: OSVClient,
    check_vulnerabilities: bool = True,
) -> PackageReport:
    """Check the health of a single package.

    Args:
        dep: The parsed dependency to check.
        pypi_client: PyPI API client.
        osv_client: OSV API client.
        check_vulnerabilities: Whether to check for vulnerabilities.

    Returns:
        A PackageReport with health status information.
    """
    report = PackageReport(
        name=dep.name,
        installed_version=dep.version or "unknown",
    )

    # Fetch PyPI info
    info = pypi_client.get_package_info(dep.name)

    if info is None:
        report.status = HealthStatus.REMOVED
        report.is_removed = True
        report.error = "Package not found on PyPI"
        return report

    # Get latest version
    latest_version = info.get("info", {}).get("version")
    report.latest_version = latest_version

    # Resolve the installed version
    resolved_version = pypi_client.resolve_version(dep, info)
    if resolved_version:
        report.installed_version = resolved_version

    # Check if yanked
    if report.installed_version and report.installed_version != "unknown":
        is_yanked = pypi_client.is_version_yanked(dep.name, report.installed_version)
        if is_yanked:
            report.status = HealthStatus.YANKED
            report.is_yanked = True
            return report

    # Check for vulnerabilities
    if check_vulnerabilities and report.installed_version != "unknown":
        vulns = osv_client.query_vulnerabilities(dep.name, report.installed_version)
        if vulns:
            report.vulnerabilities = vulns
            report.status = HealthStatus.VULNERABLE
            return report

    # Check if outdated
    if report.installed_version and latest_version:
        if report.installed_version != latest_version:
            report.status = HealthStatus.OUTDATED
            # But also check unmaintained
            last_release = pypi_client.get_last_release_date(dep.name)
            if last_release:
                report.last_release_date = last_release.strftime("%Y-%m-%d")
                days_since = (datetime.datetime.now(tz=last_release.tzinfo) - last_release).days
                if days_since > UNMAINTAINED_THRESHOLD_DAYS:
                    report.status = HealthStatus.UNMAINTAINED
            return report

    # Check if unmaintained even if not outdated
    last_release = pypi_client.get_last_release_date(dep.name)
    if last_release:
        report.last_release_date = last_release.strftime("%Y-%m-%d")
        days_since = (datetime.datetime.now(tz=last_release.tzinfo) - last_release).days
        if days_since > UNMAINTAINED_THRESHOLD_DAYS:
            report.status = HealthStatus.UNMAINTAINED
            return report

    # All checks passed
    report.status = HealthStatus.HEALTHY
    return report


def scan_project(
    project_path: str | Path,
    check_vulnerabilities: bool = True,
) -> ScanResult:
    """Scan a Python project for dependency health issues.

    This is the main entry point for scanning. It discovers dependencies,
    checks each one against PyPI and OSV, and returns a comprehensive
    scan result.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to check for vulnerabilities (can be slow).

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

    # Scan each dependency
    reports: list[PackageReport] = []
    with PyPIClient() as pypi_client, OSVClient() as osv_client:
        for dep in dependencies:
            try:
                report = check_package_health(dep, pypi_client, osv_client, check_vulnerabilities)
                reports.append(report)
            except Exception as exc:
                reports.append(
                    PackageReport(
                        name=dep.name,
                        installed_version=dep.version or "unknown",
                        status=HealthStatus.UNKNOWN,
                        error=str(exc),
                    )
                )

    return ScanResult(
        project_path=str(project_path),
        packages=reports,
        files_scanned=files_scanned,
    )
