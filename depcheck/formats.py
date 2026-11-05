"""Machine-readable output formats for depcheck scan results.

This module provides alternative renderings of a ScanResult for CI integration,
PR comments, and static analysis tooling.
"""

from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from xml.dom import minidom

from depcheck import jsonout
from depcheck.models import HealthStatus, PackageReport, ScanResult

# --- Constants ---

FORMAT_CHOICES = ("sarif", "markdown", "junit")


# --- SARIF Output ---


def _stable_guid(*parts: str) -> str:
    """Generate a deterministic GUID from input parts."""
    content = "|".join(parts)
    digest = hashlib.md5(content.encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:32]}"


def _vuln_level(severity: str) -> str:
    """Map vulnerability severity to SARIF level."""
    sev = severity.upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def _status_rule_id(status: HealthStatus) -> str:
    """Map health status to SARIF rule ID."""
    mapping = {
        HealthStatus.VULNERABLE: "depcheck/vulnerability",
        HealthStatus.OUTDATED: "depcheck/outdated",
        HealthStatus.UNMAINTAINED: "depcheck/unmaintained",
        HealthStatus.YANKED: "depcheck/yanked",
        HealthStatus.REMOVED: "depcheck/removed",
    }
    return mapping.get(status, "depcheck/unknown")


def _status_level(status: HealthStatus, severity: str | None = None) -> str:
    """Map health status to SARIF level."""
    if status == HealthStatus.VULNERABLE and severity:
        return _vuln_level(severity)
    if status in (HealthStatus.YANKED, HealthStatus.REMOVED):
        return "error"
    if status == HealthStatus.UNMAINTAINED:
        return "warning"
    return "note"


def _build_sarif_rules() -> list[dict]:
    """Build the SARIF rules array."""
    return [
        {
            "id": "depcheck/vulnerability",
            "name": "Vulnerability",
            "shortDescription": {"text": "Package has known vulnerabilities"},
            "fullDescription": {
                "text": "The package version has one or more known security vulnerabilities."
            },
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://github.com/depcheck/depcheck",
        },
        {
            "id": "depcheck/outdated",
            "name": "Outdated",
            "shortDescription": {"text": "Package is outdated"},
            "fullDescription": {"text": "A newer version of the package is available."},
            "defaultConfiguration": {"level": "note"},
            "helpUri": "https://github.com/depcheck/depcheck",
        },
        {
            "id": "depcheck/unmaintained",
            "name": "Unmaintained",
            "shortDescription": {"text": "Package appears unmaintained"},
            "fullDescription": {"text": "The package has not been updated in over a year."},
            "defaultConfiguration": {"level": "warning"},
            "helpUri": "https://github.com/depcheck/depcheck",
        },
        {
            "id": "depcheck/yanked",
            "name": "Yanked",
            "shortDescription": {"text": "Package version yanked"},
            "fullDescription": {"text": "The installed version has been yanked from PyPI."},
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://github.com/depcheck/depcheck",
        },
        {
            "id": "depcheck/removed",
            "name": "Removed",
            "shortDescription": {"text": "Package removed from PyPI"},
            "fullDescription": {"text": "The package has been removed from PyPI entirely."},
            "defaultConfiguration": {"level": "error"},
            "helpUri": "https://github.com/depcheck/depcheck",
        },
        {
            "id": "depcheck/license",
            "name": "License Non-Compliance",
            "shortDescription": {"text": "License compliance issue"},
            "fullDescription": {
                "text": "The package license does not comply with the configured policy."
            },
            "defaultConfiguration": {"level": "warning"},
            "helpUri": "https://github.com/depcheck/depcheck",
        },
    ]


def _sarif_location(file_path: str = "pyproject.toml", line: int = 1) -> dict:
    """Create a SARIF location object."""
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": file_path},
            "region": {"startLine": line},
        }
    }


def _package_properties(pkg: PackageReport) -> dict:
    """Build SARIF properties for a package."""
    props = {
        "packageName": pkg.name,
        "installedVersion": pkg.installed_version,
    }
    if pkg.latest_version:
        props["latestVersion"] = pkg.latest_version
    return props


def to_sarif(result: ScanResult) -> str:
    """Convert a ScanResult to a SARIF 2.1.0 JSON document.

    Args:
        result: The scan result to convert.

    Returns:
        A SARIF 2.1.0 JSON document as a pretty-printed string.
    """
    rules = _build_sarif_rules()
    results_list: list[dict] = []

    for pkg in result.packages:
        # Vulnerabilities - one result per vulnerability
        if pkg.vulnerabilities:
            for vuln in pkg.vulnerabilities:
                level = _vuln_level(vuln.severity)
                results_list.append(
                    {
                        "ruleId": "depcheck/vulnerability",
                        "level": level,
                        "message": {
                            "text": (
                                f"{pkg.name} {pkg.installed_version}: "
                                f"{vuln.vuln_id} ({vuln.severity}) - {vuln.summary}"
                            )
                        },
                        "locations": [_sarif_location()],
                        "properties": _package_properties(pkg)
                        | {"vulnerabilityId": vuln.vuln_id, "severity": vuln.severity},
                    }
                )

        # Outdated
        if pkg.status == HealthStatus.OUTDATED:
            results_list.append(
                {
                    "ruleId": "depcheck/outdated",
                    "level": "note",
                    "message": {
                        "text": f"{pkg.name} {pkg.installed_version}: newer version {pkg.latest_version} available"
                    },
                    "locations": [_sarif_location()],
                    "properties": _package_properties(pkg),
                }
            )

        # Unmaintained
        if pkg.status == HealthStatus.UNMAINTAINED:
            results_list.append(
                {
                    "ruleId": "depcheck/unmaintained",
                    "level": "warning",
                    "message": {
                        "text": f"{pkg.name} {pkg.installed_version}: no updates in 1+ year (unmaintained)"
                    },
                    "locations": [_sarif_location()],
                    "properties": _package_properties(pkg),
                }
            )

        # Yanked
        if pkg.status == HealthStatus.YANKED:
            results_list.append(
                {
                    "ruleId": "depcheck/yanked",
                    "level": "error",
                    "message": {
                        "text": f"{pkg.name} {pkg.installed_version}: version yanked from PyPI"
                    },
                    "locations": [_sarif_location()],
                    "properties": _package_properties(pkg),
                }
            )

        # Removed
        if pkg.status == HealthStatus.REMOVED:
            results_list.append(
                {
                    "ruleId": "depcheck/removed",
                    "level": "error",
                    "message": {
                        "text": f"{pkg.name} {pkg.installed_version}: package removed from PyPI"
                    },
                    "locations": [_sarif_location()],
                    "properties": _package_properties(pkg),
                }
            )

        # License non-compliance
        if pkg.license_info and not pkg.license_info.is_compliant:
            lic = pkg.license_info
            results_list.append(
                {
                    "ruleId": "depcheck/license",
                    "level": "warning",
                    "message": {
                        "text": f"{pkg.name} {pkg.installed_version}: license compliance issue - {lic.spdx_id or 'Unknown'} ({lic.category})"
                    },
                    "locations": [_sarif_location()],
                    "properties": _package_properties(pkg)
                    | {
                        "licenseSpdxId": lic.spdx_id,
                        "licenseCategory": lic.category,
                        "complianceNote": lic.compliance_note,
                    },
                }
            )

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "depcheck",
                        "version": "0.3.0",
                        "informationUri": "https://github.com/depcheck/depcheck",
                        "rules": rules,
                    }
                },
                "results": results_list,
            }
        ],
    }

    return jsonout.dumps(sarif_doc)


# --- Markdown Output ---


def _status_display(status: HealthStatus) -> str:
    """Get a display string for a health status."""
    mapping = {
        HealthStatus.HEALTHY: "healthy",
        HealthStatus.OUTDATED: "outdated",
        HealthStatus.VULNERABLE: "vulnerable",
        HealthStatus.UNMAINTAINED: "unmaintained",
        HealthStatus.YANKED: "yanked",
        HealthStatus.REMOVED: "removed",
        HealthStatus.UNKNOWN: "unknown",
    }
    return mapping.get(status, "unknown")


def to_markdown(result: ScanResult) -> str:
    """Convert a ScanResult to a Markdown report suitable for PR comments.

    Args:
        result: The scan result to convert.

    Returns:
        A Markdown document as a string.
    """
    lines: list[str] = []

    # Header
    lines.append("# depcheck Dependency Health Report")
    lines.append("")
    lines.append(f"**Project:** {result.project_path}")
    if result.files_scanned:
        scanned = ", ".join(result.files_scanned)
        lines.append(f"**Scanned files:** {scanned}")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Package | Installed | Latest | Status |")
    lines.append("|---------|-----------|--------|--------|")
    for pkg in result.packages:
        installed = pkg.installed_version or "\u2014"
        latest = pkg.latest_version or "\u2014"
        status = _status_display(pkg.status)
        lines.append(f"| {pkg.name} | {installed} | {latest} | {status} |")
    lines.append("")

    # Vulnerabilities section
    vuln_packages = [p for p in result.packages if p.vulnerabilities]
    if vuln_packages:
        lines.append("## Vulnerabilities")
        lines.append("")
        for pkg in vuln_packages:
            lines.append(f"### {pkg.name} {pkg.installed_version}")
            lines.append("")
            for vuln in pkg.vulnerabilities:
                lines.append(f"- **{vuln.vuln_id}** ({vuln.severity}): {vuln.summary}")
                if vuln.url:
                    lines.append(f"  - URL: {vuln.url}")
            lines.append("")

    # Licenses section
    license_packages = [p for p in result.packages if p.license_info is not None]
    if license_packages:
        lines.append("## Licenses")
        lines.append("")
        lines.append("| Package | Version | License | Category | Status |")
        lines.append("|---------|---------|---------|----------|--------|")
        for pkg in license_packages:
            lic = pkg.license_info
            if lic is None:
                continue
            status = "Compliant" if lic.is_compliant else "Non-compliant"
            if lic.compliance_note and not lic.is_compliant:
                status += f" - {lic.compliance_note}"
            lines.append(
                f"| {pkg.name} | {pkg.installed_version} | {lic.spdx_id or 'Unknown'} | {lic.category} | {status} |"
            )
        lines.append("")

    return "\n".join(lines)


# --- JUnit XML Output ---


def _escape_xml(text: str) -> str:
    """Escape special XML characters."""
    return (
        text.replace("&", "&#38;")
        .replace("<", "&#60;")
        .replace(">", "&#62;")
        .replace('"', "&#34;")
        .replace("'", "&" + "apos;")
    )


def to_junit_xml(result: ScanResult) -> str:
    """Convert a ScanResult to JUnit XML for CI dashboard integration.

    Args:
        result: The scan result to convert.

    Returns:
        A JUnit XML document as a string.
    """
    testsuites = ET.Element("testsuites")
    testsuite = ET.SubElement(testsuites, "testsuite")
    testsuite.set("name", "depcheck")
    testsuite.set("tests", "0")
    testsuite.set("failures", "0")
    testsuite.set("errors", "0")
    testsuite.set("skipped", "0")

    test_count = 0
    failure_count = 0
    error_count = 0

    for pkg in result.packages:
        test_count += 1
        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("classname", "depcheck.dependencies")
        testcase.set("name", f"{pkg.name} ({pkg.installed_version})")

        if pkg.vulnerabilities:
            failure_count += 1
            for vuln in pkg.vulnerabilities:
                failure = ET.SubElement(testcase, "failure")
                failure.set("message", _escape_xml(f"{vuln.vuln_id} ({vuln.severity})"))
                failure.set("type", "Vulnerability")
                failure.text = _escape_xml(
                    f"{pkg.name} {pkg.installed_version}: {vuln.vuln_id} ({vuln.severity}) - {vuln.summary}"
                )

        if pkg.status == HealthStatus.OUTDATED:
            failure_count += 1
            failure = ET.SubElement(testcase, "failure")
            failure.set("message", "Outdated")
            failure.set("type", "Outdated")
            failure.text = _escape_xml(
                f"{pkg.name}: installed {pkg.installed_version}, latest {pkg.latest_version} available"
            )

        if pkg.status == HealthStatus.UNMAINTAINED:
            failure_count += 1
            failure = ET.SubElement(testcase, "failure")
            failure.set("message", "Unmaintained")
            failure.set("type", "Unmaintained")
            failure.text = _escape_xml(f"{pkg.name} {pkg.installed_version}: no updates in 1+ year")

        if pkg.status == HealthStatus.YANKED:
            error_count += 1
            error = ET.SubElement(testcase, "error")
            error.set("message", "Yanked")
            error.set("type", "Yanked")
            error.text = _escape_xml(
                f"{pkg.name} {pkg.installed_version}: version yanked from PyPI"
            )

        if pkg.status == HealthStatus.REMOVED:
            error_count += 1
            error = ET.SubElement(testcase, "error")
            error.set("message", "Removed")
            error.set("type", "Removed")
            error.text = _escape_xml(
                f"{pkg.name} {pkg.installed_version}: package removed from PyPI"
            )

        if pkg.license_info and not pkg.license_info.is_compliant:
            failure_count += 1
            failure = ET.SubElement(testcase, "failure")
            failure.set("message", "License Non-Compliance")
            failure.set("type", "License")
            lic = pkg.license_info
            failure.text = _escape_xml(
                f"{pkg.name}: license {lic.spdx_id or 'Unknown'} ({lic.category}) - {lic.compliance_note or 'Non-compliant'}"
            )

    testsuite.set("tests", str(test_count))
    testsuite.set("failures", str(failure_count))
    testsuite.set("errors", str(error_count))

    rough_string = ET.tostring(testsuites, encoding="unicode")
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


# --- Dispatcher ---


def render_format(result: ScanResult, fmt: str) -> str:
    """Dispatch to the appropriate format renderer.

    Args:
        result: The scan result to render.
        fmt: The format name ("sarif", "markdown", "junit").

    Returns:
        The rendered output as a string.

    Raises:
        ValueError: If the format name is unknown.
    """
    if fmt == "sarif":
        return to_sarif(result)
    if fmt == "markdown":
        return to_markdown(result)
    if fmt == "junit":
        return to_junit_xml(result)
    supported = ", ".join(FORMAT_CHOICES)
    raise ValueError(f"Unknown format: {fmt}. Supported formats: {supported}")
