"""Software Bill of Materials (SBOM) export for depcheck.

Generates SBOM documents in industry-standard formats from Python project
dependencies. Supports:

- **CycloneDX** (JSON) — OWASP standard for supply chain transparency
- **SPDX** (JSON) — Linux Foundation standard for license compliance

Also supports a **summary format** for quick human review.

SBOMs are critical for:
- Supply chain security audits
- License compliance tracking
- Vulnerability correlation with tools like Dependabot, Snyk, OSV
- Regulatory compliance (EU CRA, US EO 14028)
"""

from __future__ import annotations

import datetime
import hashlib
import json
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import (
    HealthStatus,
    ScanResult,
    Vulnerability,
)
from depcheck.scanner import scan_project

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SPEC_VERSION = "2.4"
_SPDX_VERSION = "SPDX-2.3"
_TOOL_NAME = "depcheck"
_TOOL_VERSION = "0.1.0"

# Health status → CycloneDX severity mapping
_STATUS_SEVERITY: dict[HealthStatus, str | None] = {
    HealthStatus.VULNERABLE: "critical",
    HealthStatus.YANKED: "high",
    HealthStatus.REMOVED: "high",
    HealthStatus.UNMAINTAINED: "medium",
    HealthStatus.OUTDATED: "low",
    HealthStatus.HEALTHY: None,
    HealthStatus.UNKNOWN: None,
}

# Health status → SPDX status mapping
_SPDX_STATUS: dict[HealthStatus, str] = {
    HealthStatus.HEALTHY: "approved",
    HealthStatus.OUTDATED: "needs_review",
    HealthStatus.VULNERABLE: "rejected",
    HealthStatus.UNMAINTAINED: "needs_review",
    HealthStatus.YANKED: "rejected",
    HealthStatus.REMOVED: "rejected",
    HealthStatus.UNKNOWN: "no_assertion",
}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class SBOMComponent:
    """A single component in the SBOM."""

    name: str
    version: str
    purl: str = ""
    spdx_id: str = ""
    license_id: str = ""
    license_category: str = ""
    is_compliant: bool = True
    health_status: HealthStatus = HealthStatus.UNKNOWN
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    last_release_date: str | None = None
    is_yanked: bool = False
    is_removed: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "spdx_id": self.spdx_id,
            "license_id": self.license_id,
            "license_category": self.license_category,
            "is_compliant": self.is_compliant,
            "health_status": self.health_status.value,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "last_release_date": self.last_release_date,
            "is_yanked": self.is_yanked,
            "is_removed": self.is_removed,
        }


@dataclass
class SBOMResult:
    """Result of SBOM generation."""

    project_path: str
    format: str  # cyclonedx, spdx, summary
    components: list[SBOMComponent] = field(default_factory=list)
    files_scanned: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    generated_at: str = ""
    tool_name: str = _TOOL_NAME
    tool_version: str = _TOOL_VERSION

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.datetime.now(datetime.UTC).isoformat()

    @property
    def total(self) -> int:
        """Total number of components."""
        return len(self.components)

    @property
    def healthy_count(self) -> int:
        return sum(1 for c in self.components if c.health_status == HealthStatus.HEALTHY)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for c in self.components if c.health_status == HealthStatus.VULNERABLE)

    @property
    def license_noncompliant_count(self) -> int:
        return sum(1 for c in self.components if not c.is_compliant)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "project_path": self.project_path,
            "format": self.format,
            "generated_at": self.generated_at,
            "tool": f"{self.tool_name} {self.tool_version}",
            "total_components": self.total,
            "components": [c.to_dict() for c in self.components],
            "files_scanned": self.files_scanned,
            "errors": self.errors,
        }


# ---------------------------------------------------------------------------
# PURL generation (Package URL — https://github.com/package-url/purl-spec)
# ---------------------------------------------------------------------------


def _generate_purl(name: str, version: str) -> str:
    """Generate a PURL (Package URL) for a PyPI package.

    PURL spec: https://github.com/package-url/purl-spec
    PyPI type: "pypi"
    Namespace: None (PyPI doesn't use namespaces)
    Name: normalized (lowercase, underscores to hyphens)

    Args:
        name: Normalized package name.
        version: Version string.

    Returns:
        PURL string, e.g., "pkg:pypi/requests@2.31.0"
    """
    # PURL names use lowercase and hyphens (already normalized by scanner)
    purl_name = name.replace("_", "-").lower()
    return f"pkg:pypi/{purl_name}@{version}"


def _generate_spdx_id(name: str, version: str) -> str:
    """Generate an SPDX-ref identifier for a component.

    Args:
        name: Package name.
        version: Version string.

    Returns:
        SPDX-ref string, e.g., "SPDXRef-pkg-requests-2.31.0"
    """
    # SPDX-ref IDs must be valid identifiers: letters, numbers, hyphens, dots
    safe_name = name.replace("_", "-").replace(".", "-")
    safe_version = version.replace("+", "-plus-")
    return f"SPDXRef-pkg-{safe_name}-{safe_version}"


def _generate_bom_ref(name: str, version: str) -> str:
    """Generate a unique bom-ref for CycloneDX.

    Uses a deterministic UUID5 based on the PyPI PURL namespace.

    Args:
        name: Package name.
        version: Version string.

    Returns:
        UUID string for use as bom-ref.
    """
    purl = _generate_purl(name, version)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, purl))


# ---------------------------------------------------------------------------
# SBOM generation from scan results
# ---------------------------------------------------------------------------


def generate_sbom_from_scan(
    scan_result: ScanResult,
    include_licenses: bool = True,
) -> list[SBOMComponent]:
    """Convert a ScanResult into SBOM components.

    Args:
        scan_result: The scan result from scan_project.
        include_licenses: Whether to include license information.

    Returns:
        List of SBOMComponent objects.
    """
    components: list[SBOMComponent] = []

    for pkg in scan_result.packages:
        version = pkg.installed_version or "unknown"
        purl = _generate_purl(pkg.name, version) if version != "unknown" else ""
        spdx_id = _generate_spdx_id(pkg.name, version)

        component = SBOMComponent(
            name=pkg.name,
            version=version,
            purl=purl,
            spdx_id=spdx_id,
            health_status=pkg.status,
            vulnerabilities=pkg.vulnerabilities,
            last_release_date=pkg.last_release_date,
            is_yanked=pkg.is_yanked,
            is_removed=pkg.is_removed,
        )

        # Attach license info if available
        if include_licenses and hasattr(pkg, "license_info") and pkg.license_info:
            component.license_id = pkg.license_info.spdx_id
            component.license_category = pkg.license_info.category
            component.is_compliant = pkg.license_info.is_compliant

        components.append(component)

    return components


def generate_sbom(
    project_path: str | Path,
    check_vulnerabilities: bool = True,
    include_licenses: bool = True,
) -> SBOMResult:
    """Generate an SBOM for a Python project.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to check for vulnerabilities.
        include_licenses: Whether to include license information.

    Returns:
        SBOMResult with all components and metadata.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return SBOMResult(
            project_path=str(project_path),
            format="unknown",
            errors=[f"Path is not a directory: {project_path}"],
        )

    # Run a full scan to get health + vulnerability info
    scan_result = scan_project(
        project_path=str(project_path),
        check_vulnerabilities=check_vulnerabilities,
    )

    components = generate_sbom_from_scan(scan_result, include_licenses=include_licenses)

    return SBOMResult(
        project_path=str(project_path),
        format="raw",
        components=components,
        files_scanned=scan_result.files_scanned,
        errors=scan_result.errors,
    )


# ---------------------------------------------------------------------------
# CycloneDX JSON format
# ---------------------------------------------------------------------------


def to_cyclonedx(sbom: SBOMResult) -> dict[str, Any]:
    """Convert SBOM result to CycloneDX JSON format.

    CycloneDX is an OWASP standard for supply chain transparency.
    Spec: https://cyclonedx.org/docs/1.6/json/

    Args:
        sbom: The SBOM result to convert.

    Returns:
        Dictionary representing a CycloneDX JSON document.
    """
    serial_number = f"urn:uuid:{uuid.uuid4()}"

    components: list[dict[str, Any]] = []
    for comp in sbom.components:
        entry: dict[str, Any] = {
            "type": "library",
            "bom-ref": _generate_bom_ref(comp.name, comp.version),
            "name": comp.name,
            "version": comp.version,
        }

        if comp.purl:
            entry["purl"] = comp.purl

        # License
        if comp.license_id:
            entry["licenses"] = [
                {
                    "license": {
                        "id": comp.license_id,
                    }
                }
            ]

        # Vulnerabilities → CycloneDX affects
        if comp.vulnerabilities:
            entry["evidence"] = {
                "occurrences": [
                    {
                        "location": comp.purl or f"{comp.name}@{comp.version}",
                    }
                ]
            }

        # Health-based description
        if (
            comp.health_status != HealthStatus.HEALTHY
            and comp.health_status != HealthStatus.UNKNOWN
        ):
            entry["description"] = f"Health status: {comp.health_status.value}"

        # Yanked / removed
        if comp.is_yanked:
            entry["tags"] = ["yanked"]
        elif comp.is_removed:
            entry["tags"] = ["removed"]

        # External references
        entry["externalReferences"] = [
            {
                "type": "distribution",
                "url": f"https://pypi.org/project/{comp.name}/{comp.version}/",
            }
        ]

        components.append(entry)

    # Vulnerabilities section
    vulnerabilities: list[dict[str, Any]] = []
    for comp in sbom.components:
        for vuln in comp.vulnerabilities:
            vuln_entry: dict[str, Any] = {
                "bom-ref": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, vuln.vuln_id)}",
                "id": vuln.vuln_id,
                "source": {
                    "url": vuln.url,
                },
                "ratings": [],
                "affects": [
                    {
                        "ref": _generate_bom_ref(comp.name, comp.version),
                    }
                ],
            }

            if vuln.severity and vuln.severity != "UNKNOWN":
                severity_map = {
                    "LOW": "low",
                    "MEDIUM": "medium",
                    "HIGH": "high",
                    "CRITICAL": "critical",
                }
                vuln_entry["ratings"] = [
                    {
                        "severity": severity_map.get(vuln.severity.upper(), "unknown"),
                        "source": {
                            "url": vuln.url,
                        },
                    }
                ]

            if vuln.summary:
                vuln_entry["description"] = vuln.summary

            if vuln.aliases:
                vuln_entry["cwe"] = [a for a in vuln.aliases if a.startswith("CWE-")]

            vulnerabilities.append(vuln_entry)

    doc: dict[str, Any] = {
        "$schema": "https://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": sbom.generated_at,
            "tools": [
                {
                    "name": sbom.tool_name,
                    "version": sbom.tool_version,
                }
            ],
            "component": {
                "type": "application",
                "name": Path(sbom.project_path).name,
                "bom-ref": str(uuid.uuid5(uuid.NAMESPACE_URL, sbom.project_path)),
            },
        },
        "components": components,
    }

    if vulnerabilities:
        doc["vulnerabilities"] = vulnerabilities

    return doc


# ---------------------------------------------------------------------------
# SPDX JSON format
# ---------------------------------------------------------------------------


def to_spdx(sbom: SBOMResult) -> dict[str, Any]:
    """Convert SBOM result to SPDX JSON format.

    SPDX is a Linux Foundation standard for license compliance.
    Spec: https://spdx.github.io/spdx-spec/v2.3/

    Args:
        sbom: The SBOM result to convert.

    Returns:
        Dictionary representing an SPDX JSON document.
    """
    spdx_id = f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:12]}"
    namespace = f"https://depcheck.dev/sbom/{Path(sbom.project_path).name}"

    packages: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []

    for comp in sbom.components:
        pkg_id = comp.spdx_id or _generate_spdx_id(comp.name, comp.version)

        pkg_entry: dict[str, Any] = {
            "SPDXID": pkg_id,
            "name": comp.name,
            "versionInfo": comp.version,
            "downloadLocation": f"https://pypi.org/project/{comp.name}/{comp.version}/#files",
            "filesAnalyzed": False,
            "packageVerificationCode": {
                "packageVerificationCodeValue": hashlib.sha256(
                    f"{comp.name}@{comp.version}".encode()
                ).hexdigest(),
            },
        }

        # License
        if comp.license_id:
            pkg_entry["licenseConcluded"] = comp.license_id
            pkg_entry["licenseDeclared"] = comp.license_id
        else:
            pkg_entry["licenseConcluded"] = "NOASSERTION"
            pkg_entry["licenseDeclared"] = "NOASSERTION"

        # Supplier
        pkg_entry["supplier"] = f"Organization: PyPI ({comp.name})"

        # External references
        external_refs: list[dict[str, Any]] = [
            {
                "referenceCategory": "PACKAGE_MANAGER",
                "referenceType": "purl",
                "referenceLocator": comp.purl,
            }
        ]

        # Health status as a SECURITY reference
        if (
            comp.health_status != HealthStatus.HEALTHY
            and comp.health_status != HealthStatus.UNKNOWN
        ):
            external_refs.append(
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "advisory",
                    "referenceLocator": f"https://pypi.org/project/{comp.name}/",
                }
            )

        pkg_entry["externalReferences"] = external_refs

        # Relationship: DESCRIBES (project depends on this package)
        relationships.append(
            {
                "spdxElementId": spdx_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": pkg_id,
            }
        )

        packages.append(pkg_entry)

    doc: dict[str, Any] = {
        "spdxVersion": _SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": spdx_id,
        "name": Path(sbom.project_path).name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": sbom.generated_at,
            "creators": [
                f"Tool: {sbom.tool_name}-{sbom.tool_version}",
                "Organization: depcheck",
            ],
        },
        "packages": packages,
        "relationships": relationships,
    }

    return doc


# ---------------------------------------------------------------------------
# Summary format (human-readable)
# ---------------------------------------------------------------------------


def to_summary(sbom: SBOMResult) -> dict[str, Any]:
    """Convert SBOM to a summary dictionary for quick review.

    This is not a standard format but provides a concise overview
    suitable for human review or CI reports.

    Args:
        sbom: The SBOM result to convert.

    Returns:
        Dictionary with summary information.
    """
    # License breakdown
    license_counts: dict[str, int] = {}
    for comp in sbom.components:
        lid = comp.license_id or "UNKNOWN"
        license_counts[lid] = license_counts.get(lid, 0) + 1

    # Health breakdown
    health_counts: dict[str, int] = {}
    for comp in sbom.components:
        status = comp.health_status.value
        health_counts[status] = health_counts.get(status, 0) + 1

    # Vulnerability summary
    total_vulns = sum(len(c.vulnerabilities) for c in sbom.components)
    high_vulns = sum(
        1
        for c in sbom.components
        for v in c.vulnerabilities
        if v.severity.upper() in ("HIGH", "CRITICAL")
    )

    return {
        "project_path": sbom.project_path,
        "generated_at": sbom.generated_at,
        "tool": f"{sbom.tool_name} {sbom.tool_version}",
        "total_components": sbom.total,
        "health_summary": health_counts,
        "license_summary": license_counts,
        "noncompliant_licenses": sbom.license_noncompliant_count,
        "vulnerabilities": {
            "total": total_vulns,
            "high_or_critical": high_vulns,
        },
        "files_scanned": sbom.files_scanned,
        "errors": sbom.errors,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_cyclonedx(sbom: SBOMResult, console: Console | None = None) -> str:
    """Render SBOM as CycloneDX JSON string.

    Args:
        sbom: The SBOM result.
        console: Optional Rich console (not used, kept for API consistency).

    Returns:
        JSON string of the CycloneDX document.
    """
    doc = to_cyclonedx(sbom)
    return json.dumps(doc, indent=2)


def render_spdx(sbom: SBOMResult, console: Console | None = None) -> str:
    """Render SBOM as SPDX JSON string.

    Args:
        sbom: The SBOM result.
        console: Optional Rich console.

    Returns:
        JSON string of the SPDX document.
    """
    doc = to_spdx(sbom)
    return json.dumps(doc, indent=2)


def render_summary_json(sbom: SBOMResult, console: Console | None = None) -> str:
    """Render SBOM summary as JSON string.

    Args:
        sbom: The SBOM result.
        console: Optional Rich console.

    Returns:
        JSON string of the summary.
    """
    summary = to_summary(sbom)
    return json.dumps(summary, indent=2)


def render_summary_table(sbom: SBOMResult, console: Console | None = None) -> None:
    """Render SBOM summary as a Rich table.

    Args:
        sbom: The SBOM result.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    # Header
    console.print()
    console.print(
        Panel(
            f"[bold]depcheck export[/bold] — Software Bill of Materials\n"
            f"[dim]Project: {sbom.project_path}[/dim]\n"
            f"[dim]Generated: {sbom.generated_at}[/dim]",
            border_style="blue",
        )
    )

    if sbom.errors and not sbom.components:
        for error in sbom.errors:
            console.print(f"[red]Error:[/red] {error}")
        return

    # Component table
    table = Table(
        title="SBOM Components",
        show_header=True,
        header_style="bold cyan",
        show_lines=False,
        expand=True,
    )

    table.add_column("Package", style="bold", min_width=20)
    table.add_column("Version", min_width=12)
    table.add_column("License", min_width=15)
    table.add_column("PURL", min_width=25, no_wrap=True)
    table.add_column("Status", width=8, justify="center")

    for comp in sbom.components:
        status_icon = _status_icon(comp.health_status)
        status_color = _status_color(comp.health_status)

        license_display = comp.license_id or "—"
        if not comp.is_compliant and comp.license_id:
            license_display = f"[red]{comp.license_id} ✗[/red]"

        purl_display = comp.purl or "—"

        table.add_row(
            comp.name,
            comp.version,
            license_display,
            purl_display,
            f"[{status_color}]{status_icon}[/{status_color}]",
        )

    console.print(table)

    # Vulnerability table (if any)
    vuln_components = [c for c in sbom.components if c.vulnerabilities]
    if vuln_components:
        console.print()
        vuln_table = Table(
            title="⚠️ Vulnerabilities in SBOM",
            show_header=True,
            header_style="bold red",
            show_lines=False,
            expand=True,
        )
        vuln_table.add_column("Package", style="bold", min_width=20)
        vuln_table.add_column("ID", min_width=15)
        vuln_table.add_column("Severity", min_width=10)
        vuln_table.add_column("Summary", min_width=40)

        for comp in vuln_components:
            for vuln in comp.vulnerabilities:
                severity_color = {
                    "HIGH": "red",
                    "CRITICAL": "red bold",
                    "MEDIUM": "yellow",
                    "LOW": "green",
                }.get(vuln.severity.upper(), "white")
                vuln_table.add_row(
                    comp.name,
                    vuln.vuln_id,
                    f"[{severity_color}]{vuln.severity}[/{severity_color}]",
                    vuln.summary[:60] + ("..." if len(vuln.summary) > 60 else ""),
                )

        console.print(vuln_table)

    # Summary
    console.print()
    summary = to_summary(sbom)
    summary_parts: list[str] = []
    summary_parts.append(f"[bold]Total:[/bold] {sbom.total} components")

    for status, count in summary["health_summary"].items():
        icon, color = _health_style(status)
        if count > 0:
            summary_parts.append(f"[{color}]{icon} {status}: {count}[/{color}]")

    if summary["noncompliant_licenses"] > 0:
        summary_parts.append(
            f"[red]⚖ Non-compliant licenses: {summary['noncompliant_licenses']}[/red]"
        )

    vuln_info = summary["vulnerabilities"]
    if vuln_info["total"] > 0:
        summary_parts.append(
            f"[red]🔴 Vulnerabilities: {vuln_info['total']} "
            f"({vuln_info['high_or_critical']} high/critical)[/red]"
        )

    if sbom.files_scanned:
        summary_parts.append(f"\n[dim]Scanned: {', '.join(sbom.files_scanned)}[/dim]")

    console.print(Panel("\n".join(summary_parts), title="SBOM Summary", border_style="blue"))
    console.print()


def _status_icon(status: HealthStatus) -> str:
    """Get the icon for a health status."""
    styles: dict[HealthStatus, str] = {
        HealthStatus.HEALTHY: "🟢",
        HealthStatus.OUTDATED: "🟡",
        HealthStatus.VULNERABLE: "🔴",
        HealthStatus.UNMAINTAINED: "🟡",
        HealthStatus.YANKED: "🔴",
        HealthStatus.REMOVED: "🔴",
        HealthStatus.UNKNOWN: "⚪",
    }
    return styles.get(status, "⚪")


def _status_color(status: HealthStatus) -> str:
    """Get the color for a health status."""
    colors: dict[HealthStatus, str] = {
        HealthStatus.HEALTHY: "green",
        HealthStatus.OUTDATED: "yellow",
        HealthStatus.VULNERABLE: "red",
        HealthStatus.UNMAINTAINED: "yellow",
        HealthStatus.YANKED: "red",
        HealthStatus.REMOVED: "red",
        HealthStatus.UNKNOWN: "white",
    }
    return colors.get(status, "white")


def _health_style(status_value: str) -> tuple[str, str]:
    """Get display style from a status value string."""
    try:
        status = HealthStatus(status_value)
        return _status_icon(status), _status_color(status)
    except ValueError:
        return "⚪", "white"


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------


def write_sbom_to_file(
    sbom: SBOMResult,
    format: str,
    output_path: str | Path | None = None,
) -> Path:
    """Write an SBOM to a file.

    Args:
        sbom: The SBOM result.
        format: Output format (cyclonedx, spdx, summary).
        output_path: Output file path. If None, auto-generates from project name.

    Returns:
        Path to the written file.
    """
    if format == "cyclonedx":
        content = render_cyclonedx(sbom)
        suffix = ".cdx.json"
    elif format == "spdx":
        content = render_spdx(sbom)
        suffix = ".spdx.json"
    elif format == "summary":
        content = render_summary_json(sbom)
        suffix = ".sbom.json"
    else:
        raise ValueError(f"Unknown SBOM format: {format}")

    if output_path is None:
        project_name = Path(sbom.project_path).name
        output_path = Path(f"{project_name}{suffix}")
    else:
        output_path = Path(output_path)

    output_path.write_text(content, encoding="utf-8")
    return output_path
