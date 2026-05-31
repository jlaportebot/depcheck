"""Tests for depcheck export (SBOM generation) module."""

from __future__ import annotations

import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from rich.console import Console

from depcheck.cli import main
from depcheck.export import (
    SBOMComponent,
    SBOMResult,
    _generate_bom_ref,
    _generate_purl,
    _generate_spdx_id,
    generate_sbom,
    generate_sbom_from_scan,
    render_cyclonedx,
    render_spdx,
    render_summary_json,
    render_summary_table,
    to_cyclonedx,
    to_spdx,
    to_summary,
    write_sbom_to_file,
)
from depcheck.models import (
    HealthStatus,
    PackageReport,
    ScanResult,
    Vulnerability,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_vuln(
    vuln_id: str = "CVE-2023-1234",
    summary: str = "Test vulnerability",
    severity: str = "HIGH",
) -> Vulnerability:
    return Vulnerability(
        vuln_id=vuln_id,
        summary=summary,
        severity=severity,
        url=f"https://osv.dev/vulnerability/{vuln_id}",
        aliases=[],
    )


def _make_scan_result() -> ScanResult:
    """Create a sample ScanResult for testing."""
    return ScanResult(
        project_path="/tmp/test-project",
        packages=[
            PackageReport(
                name="requests",
                installed_version="2.31.0",
                latest_version="2.31.0",
                status=HealthStatus.HEALTHY,
            ),
            PackageReport(
                name="flask",
                installed_version="2.0.0",
                latest_version="3.0.0",
                status=HealthStatus.OUTDATED,
            ),
            PackageReport(
                name="old-lib",
                installed_version="1.0.0",
                latest_version="1.0.0",
                status=HealthStatus.VULNERABLE,
                vulnerabilities=[_make_vuln()],
            ),
        ],
        files_scanned=["/tmp/test-project/requirements.txt"],
    )


def _make_sbom_result() -> SBOMResult:
    """Create a sample SBOMResult for testing."""
    components = [
        SBOMComponent(
            name="requests",
            version="2.31.0",
            purl="pkg:pypi/requests@2.31.0",
            spdx_id="SPDXRef-pkg-requests-2.31.0",
            license_id="Apache-2.0",
            license_category="permissive",
            is_compliant=True,
            health_status=HealthStatus.HEALTHY,
        ),
        SBOMComponent(
            name="flask",
            version="3.0.0",
            purl="pkg:pypi/flask@3.0.0",
            spdx_id="SPDXRef-pkg-flask-3.0.0",
            license_id="BSD-3-Clause",
            license_category="permissive",
            is_compliant=True,
            health_status=HealthStatus.OUTDATED,
        ),
        SBOMComponent(
            name="vuln-pkg",
            version="1.0.0",
            purl="pkg:pypi/vuln-pkg@1.0.0",
            spdx_id="SPDXRef-pkg-vuln-pkg-1.0.0",
            license_id="GPL-3.0",
            license_category="copyleft",
            is_compliant=False,
            health_status=HealthStatus.VULNERABLE,
            vulnerabilities=[_make_vuln()],
        ),
        SBOMComponent(
            name="unknown-pkg",
            version="0.5.0",
            purl="pkg:pypi/unknown-pkg@0.5.0",
            spdx_id="SPDXRef-pkg-unknown-pkg-0.5.0",
            license_id="",
            is_compliant=False,
            health_status=HealthStatus.UNKNOWN,
        ),
    ]
    return SBOMResult(
        project_path="/tmp/test-project",
        format="raw",
        components=components,
        files_scanned=["/tmp/test-project/requirements.txt"],
    )


# ---------------------------------------------------------------------------
# PURL and ID generation
# ---------------------------------------------------------------------------


class TestPurlGeneration:
    """Tests for PURL (Package URL) generation."""

    def test_basic_purl(self) -> None:
        assert _generate_purl("requests", "2.31.0") == "pkg:pypi/requests@2.31.0"

    def test_normalized_name(self) -> None:
        assert _generate_purl("my_package", "1.0.0") == "pkg:pypi/my-package@1.0.0"

    def test_lowercase(self) -> None:
        assert _generate_purl("Flask", "3.0.0") == "pkg:pypi/flask@3.0.0"


class TestSpdxIdGeneration:
    """Tests for SPDX-ref ID generation."""

    def test_basic_id(self) -> None:
        assert _generate_spdx_id("requests", "2.31.0") == "SPDXRef-pkg-requests-2.31.0"

    def test_underscores_replaced(self) -> None:
        assert _generate_spdx_id("my_pkg", "1.0") == "SPDXRef-pkg-my-pkg-1.0"


class TestBomRefGeneration:
    """Tests for CycloneDX bom-ref generation."""

    def test_deterministic(self) -> None:
        ref1 = _generate_bom_ref("requests", "2.31.0")
        ref2 = _generate_bom_ref("requests", "2.31.0")
        assert ref1 == ref2

    def test_different_packages_different_refs(self) -> None:
        ref1 = _generate_bom_ref("requests", "2.31.0")
        ref2 = _generate_bom_ref("flask", "3.0.0")
        assert ref1 != ref2

    def test_is_uuid(self) -> None:
        ref = _generate_bom_ref("requests", "2.31.0")
        # UUID format: 8-4-4-4-12
        parts = ref.split("-")
        assert len(parts) == 5


# ---------------------------------------------------------------------------
# SBOMComponent
# ---------------------------------------------------------------------------


class TestSBOMComponent:
    """Tests for SBOMComponent data model."""

    def test_to_dict(self) -> None:
        comp = SBOMComponent(
            name="requests",
            version="2.31.0",
            purl="pkg:pypi/requests@2.31.0",
            spdx_id="SPDXRef-pkg-requests-2.31.0",
            license_id="Apache-2.0",
            license_category="permissive",
            is_compliant=True,
            health_status=HealthStatus.HEALTHY,
        )
        d = comp.to_dict()
        assert d["name"] == "requests"
        assert d["version"] == "2.31.0"
        assert d["purl"] == "pkg:pypi/requests@2.31.0"
        assert d["license_id"] == "Apache-2.0"
        assert d["health_status"] == "healthy"

    def test_to_dict_with_vulnerabilities(self) -> None:
        comp = SBOMComponent(
            name="vuln-pkg",
            version="1.0.0",
            health_status=HealthStatus.VULNERABLE,
            vulnerabilities=[_make_vuln()],
        )
        d = comp.to_dict()
        assert len(d["vulnerabilities"]) == 1
        assert d["vulnerabilities"][0]["id"] == "CVE-2023-1234"


# ---------------------------------------------------------------------------
# SBOMResult
# ---------------------------------------------------------------------------


class TestSBOMResult:
    """Tests for SBOMResult data model."""

    def test_total(self) -> None:
        sbom = _make_sbom_result()
        assert sbom.total == 4

    def test_healthy_count(self) -> None:
        sbom = _make_sbom_result()
        assert sbom.healthy_count == 1

    def test_vulnerable_count(self) -> None:
        sbom = _make_sbom_result()
        assert sbom.vulnerable_count == 1

    def test_license_noncompliant_count(self) -> None:
        sbom = _make_sbom_result()
        assert sbom.license_noncompliant_count == 2  # GPL-3.0 + unknown

    def test_to_dict(self) -> None:
        sbom = _make_sbom_result()
        d = sbom.to_dict()
        assert d["project_path"] == "/tmp/test-project"
        assert d["total_components"] == 4
        assert len(d["components"]) == 4

    def test_auto_generated_at(self) -> None:
        sbom = SBOMResult(project_path="/tmp/test", format="raw")
        assert sbom.generated_at  # Should be auto-populated


# ---------------------------------------------------------------------------
# generate_sbom_from_scan
# ---------------------------------------------------------------------------


class TestGenerateSbomFromScan:
    """Tests for converting scan results to SBOM components."""

    def test_basic_conversion(self) -> None:
        scan = _make_scan_result()
        components = generate_sbom_from_scan(scan)
        assert len(components) == 3

    def test_purl_generated(self) -> None:
        scan = _make_scan_result()
        components = generate_sbom_from_scan(scan)
        requests_comp = next(c for c in components if c.name == "requests")
        assert requests_comp.purl == "pkg:pypi/requests@2.31.0"

    def test_spdx_id_generated(self) -> None:
        scan = _make_scan_result()
        components = generate_sbom_from_scan(scan)
        requests_comp = next(c for c in components if c.name == "requests")
        assert requests_comp.spdx_id == "SPDXRef-pkg-requests-2.31.0"

    def test_health_status_preserved(self) -> None:
        scan = _make_scan_result()
        components = generate_sbom_from_scan(scan)
        flask_comp = next(c for c in components if c.name == "flask")
        assert flask_comp.health_status == HealthStatus.OUTDATED

    def test_vulnerabilities_preserved(self) -> None:
        scan = _make_scan_result()
        components = generate_sbom_from_scan(scan)
        vuln_comp = next(c for c in components if c.name == "old-lib")
        assert len(vuln_comp.vulnerabilities) == 1

    def test_without_licenses(self) -> None:
        scan = _make_scan_result()
        components = generate_sbom_from_scan(scan, include_licenses=False)
        for comp in components:
            assert comp.license_id == ""


# ---------------------------------------------------------------------------
# CycloneDX format
# ---------------------------------------------------------------------------


class TestCycloneDx:
    """Tests for CycloneDX JSON output."""

    def test_structure(self) -> None:
        sbom = _make_sbom_result()
        doc = to_cyclonedx(sbom)
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.6"
        assert "serialNumber" in doc
        assert "metadata" in doc
        assert "components" in doc

    def test_metadata(self) -> None:
        sbom = _make_sbom_result()
        doc = to_cyclonedx(sbom)
        assert doc["metadata"]["tools"][0]["name"] == "depcheck"
        assert doc["metadata"]["component"]["type"] == "application"

    def test_components(self) -> None:
        sbom = _make_sbom_result()
        doc = to_cyclonedx(sbom)
        assert len(doc["components"]) == 4

        # Check first component (requests)
        req = next(c for c in doc["components"] if c["name"] == "requests")
        assert req["type"] == "library"
        assert req["version"] == "2.31.0"
        assert req["purl"] == "pkg:pypi/requests@2.31.0"
        assert "bom-ref" in req

    def test_component_license(self) -> None:
        sbom = _make_sbom_result()
        doc = to_cyclonedx(sbom)
        req = next(c for c in doc["components"] if c["name"] == "requests")
        assert "licenses" in req
        assert req["licenses"][0]["license"]["id"] == "Apache-2.0"

    def test_component_no_license(self) -> None:
        sbom = _make_sbom_result()
        doc = to_cyclonedx(sbom)
        unknown = next(c for c in doc["components"] if c["name"] == "unknown-pkg")
        assert "licenses" not in unknown

    def test_vulnerabilities_section(self) -> None:
        sbom = _make_sbom_result()
        doc = to_cyclonedx(sbom)
        assert "vulnerabilities" in doc
        assert len(doc["vulnerabilities"]) == 1
        vuln = doc["vulnerabilities"][0]
        assert vuln["id"] == "CVE-2023-1234"
        assert vuln["ratings"][0]["severity"] == "high"

    def test_vulnerability_affects(self) -> None:
        sbom = _make_sbom_result()
        doc = to_cyclonedx(sbom)
        vuln = doc["vulnerabilities"][0]
        assert len(vuln["affects"]) == 1
        assert "ref" in vuln["affects"][0]

    def test_yanked_tag(self) -> None:
        comp = SBOMComponent(
            name="yanked-pkg",
            version="1.0.0",
            purl="pkg:pypi/yanked-pkg@1.0.0",
            health_status=HealthStatus.YANKED,
            is_yanked=True,
        )
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=[comp])
        doc = to_cyclonedx(sbom)
        assert doc["components"][0]["tags"] == ["yanked"]

    def test_removed_tag(self) -> None:
        comp = SBOMComponent(
            name="removed-pkg",
            version="1.0.0",
            purl="pkg:pypi/removed-pkg@1.0.0",
            health_status=HealthStatus.REMOVED,
            is_removed=True,
        )
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=[comp])
        doc = to_cyclonedx(sbom)
        assert doc["components"][0]["tags"] == ["removed"]

    def test_no_vulnerabilities_when_clean(self) -> None:
        comp = SBOMComponent(
            name="clean-pkg",
            version="1.0.0",
            health_status=HealthStatus.HEALTHY,
        )
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=[comp])
        doc = to_cyclonedx(sbom)
        assert "vulnerabilities" not in doc

    def test_external_references(self) -> None:
        sbom = _make_sbom_result()
        doc = to_cyclonedx(sbom)
        req = next(c for c in doc["components"] if c["name"] == "requests")
        assert len(req["externalReferences"]) == 1
        assert "pypi.org" in req["externalReferences"][0]["url"]

    def test_render_cyclonedx_valid_json(self) -> None:
        sbom = _make_sbom_result()
        output = render_cyclonedx(sbom)
        data = json.loads(output)
        assert data["bomFormat"] == "CycloneDX"


# ---------------------------------------------------------------------------
# SPDX format
# ---------------------------------------------------------------------------


class TestSpdx:
    """Tests for SPDX JSON output."""

    def test_structure(self) -> None:
        sbom = _make_sbom_result()
        doc = to_spdx(sbom)
        assert doc["spdxVersion"] == "SPDX-2.3"
        assert doc["dataLicense"] == "CC0-1.0"
        assert "SPDXID" in doc
        assert "name" in doc
        assert "packages" in doc
        assert "relationships" in doc

    def test_packages(self) -> None:
        sbom = _make_sbom_result()
        doc = to_spdx(sbom)
        assert len(doc["packages"]) == 4

        req = next(p for p in doc["packages"] if p["name"] == "requests")
        assert req["versionInfo"] == "2.31.0"
        assert req["licenseConcluded"] == "Apache-2.0"
        assert req["SPDXID"] == "SPDXRef-pkg-requests-2.31.0"

    def test_license_noassertion(self) -> None:
        sbom = _make_sbom_result()
        doc = to_spdx(sbom)
        unknown = next(p for p in doc["packages"] if p["name"] == "unknown-pkg")
        assert unknown["licenseConcluded"] == "NOASSERTION"
        assert unknown["licenseDeclared"] == "NOASSERTION"

    def test_purl_external_ref(self) -> None:
        sbom = _make_sbom_result()
        doc = to_spdx(sbom)
        req = next(p for p in doc["packages"] if p["name"] == "requests")
        purl_refs = [r for r in req["externalReferences"] if r["referenceType"] == "purl"]
        assert len(purl_refs) == 1
        assert purl_refs[0]["referenceLocator"] == "pkg:pypi/requests@2.31.0"

    def test_relationships(self) -> None:
        sbom = _make_sbom_result()
        doc = to_spdx(sbom)
        assert len(doc["relationships"]) == 4
        # All should be DEPENDS_ON
        for rel in doc["relationships"]:
            assert rel["relationshipType"] == "DEPENDS_ON"

    def test_creation_info(self) -> None:
        sbom = _make_sbom_result()
        doc = to_spdx(sbom)
        assert "created" in doc["creationInfo"]
        assert any("depcheck" in c for c in doc["creationInfo"]["creators"])

    def test_security_ref_for_unhealthy(self) -> None:
        sbom = _make_sbom_result()
        doc = to_spdx(sbom)
        vuln_pkg = next(p for p in doc["packages"] if p["name"] == "vuln-pkg")
        sec_refs = [
            r for r in vuln_pkg["externalReferences"] if r["referenceCategory"] == "SECURITY"
        ]
        assert len(sec_refs) == 1

    def test_render_spdx_valid_json(self) -> None:
        sbom = _make_sbom_result()
        output = render_spdx(sbom)
        data = json.loads(output)
        assert data["spdxVersion"] == "SPDX-2.3"


# ---------------------------------------------------------------------------
# Summary format
# ---------------------------------------------------------------------------


class TestSummary:
    """Tests for summary output."""

    def test_basic_summary(self) -> None:
        sbom = _make_sbom_result()
        summary = to_summary(sbom)
        assert summary["total_components"] == 4
        assert "health_summary" in summary
        assert "license_summary" in summary
        assert "vulnerabilities" in summary

    def test_health_summary(self) -> None:
        sbom = _make_sbom_result()
        summary = to_summary(sbom)
        assert summary["health_summary"]["healthy"] == 1
        assert summary["health_summary"]["outdated"] == 1
        assert summary["health_summary"]["vulnerable"] == 1

    def test_license_summary(self) -> None:
        sbom = _make_sbom_result()
        summary = to_summary(sbom)
        assert summary["license_summary"]["Apache-2.0"] == 1
        assert summary["license_summary"]["BSD-3-Clause"] == 1
        assert summary["license_summary"]["GPL-3.0"] == 1

    def test_noncompliant_count(self) -> None:
        sbom = _make_sbom_result()
        summary = to_summary(sbom)
        assert summary["noncompliant_licenses"] == 2

    def test_vulnerability_summary(self) -> None:
        sbom = _make_sbom_result()
        summary = to_summary(sbom)
        assert summary["vulnerabilities"]["total"] == 1
        assert summary["vulnerabilities"]["high_or_critical"] == 1

    def test_render_summary_json_valid(self) -> None:
        sbom = _make_sbom_result()
        output = render_summary_json(sbom)
        data = json.loads(output)
        assert data["total_components"] == 4


class TestRenderSummaryTable:
    """Tests for Rich table rendering of summary."""

    def test_basic_render(self) -> None:
        sbom = _make_sbom_result()
        buf = StringIO()
        console = Console(file=buf, width=160, force_terminal=True)
        render_summary_table(sbom, console=console)
        output = buf.getvalue()
        assert "requests" in output
        assert "SBOM" in output

    def test_render_empty_result(self) -> None:
        sbom = SBOMResult(
            project_path="/tmp/empty",
            format="raw",
            errors=["No dependencies found"],
        )
        buf = StringIO()
        console = Console(file=buf, width=160, force_terminal=True)
        render_summary_table(sbom, console=console)
        output = buf.getvalue()
        assert "Error" in output

    def test_render_noncompliant_license(self) -> None:
        comp = SBOMComponent(
            name="gpl-pkg",
            version="1.0.0",
            license_id="GPL-3.0",
            is_compliant=False,
            health_status=HealthStatus.HEALTHY,
        )
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=[comp])
        buf = StringIO()
        console = Console(file=buf, width=160, force_terminal=True)
        render_summary_table(sbom, console=console)
        output = buf.getvalue()
        assert "gpl-pkg" in output


# ---------------------------------------------------------------------------
# File output
# ---------------------------------------------------------------------------


class TestWriteSbomToFile:
    """Tests for writing SBOM to file."""

    def test_cyclonedx_file(self, tmp_path: Path) -> None:
        sbom = _make_sbom_result()
        out = tmp_path / "bom.cdx.json"
        written = write_sbom_to_file(sbom, "cyclonedx", output_path=out)
        assert written.exists()
        data = json.loads(written.read_text())
        assert data["bomFormat"] == "CycloneDX"

    def test_spdx_file(self, tmp_path: Path) -> None:
        sbom = _make_sbom_result()
        out = tmp_path / "bom.spdx.json"
        written = write_sbom_to_file(sbom, "spdx", output_path=out)
        assert written.exists()
        data = json.loads(written.read_text())
        assert data["spdxVersion"] == "SPDX-2.3"

    def test_summary_file(self, tmp_path: Path) -> None:
        sbom = _make_sbom_result()
        out = tmp_path / "sbom.json"
        written = write_sbom_to_file(sbom, "summary", output_path=out)
        assert written.exists()
        data = json.loads(written.read_text())
        assert data["total_components"] == 4

    def test_auto_filename(self) -> None:
        sbom = _make_sbom_result()
        written = write_sbom_to_file(sbom, "cyclonedx")
        try:
            assert written.exists()
            assert written.name.endswith(".cdx.json")
        finally:
            written.unlink(missing_ok=True)

    def test_invalid_format(self) -> None:
        sbom = _make_sbom_result()
        with pytest.raises(ValueError, match="Unknown SBOM format"):
            write_sbom_to_file(sbom, "invalid")


# ---------------------------------------------------------------------------
# generate_sbom (integration)
# ---------------------------------------------------------------------------


class TestGenerateSbom:
    """Integration tests for generate_sbom with mocked scan_project."""

    def test_nonexistent_directory(self) -> None:
        sbom = generate_sbom("/nonexistent/path")
        assert len(sbom.errors) > 0
        assert sbom.components == []

    def test_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom = generate_sbom(tmpdir)
            assert len(sbom.errors) > 0

    def test_with_requirements(self) -> None:
        """Test SBOM generation with a real requirements.txt (mocked APIs)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "requirements.txt"
            req_path.write_text("requests==2.31.0\nflask==3.0.0\n")

            mock_scan_result = ScanResult(
                project_path=tmpdir,
                packages=[
                    PackageReport(
                        name="requests",
                        installed_version="2.31.0",
                        latest_version="2.31.0",
                        status=HealthStatus.HEALTHY,
                    ),
                    PackageReport(
                        name="flask",
                        installed_version="3.0.0",
                        latest_version="3.0.0",
                        status=HealthStatus.HEALTHY,
                    ),
                ],
                files_scanned=[str(req_path)],
            )

            with patch("depcheck.export.scan_project", return_value=mock_scan_result):
                sbom = generate_sbom(tmpdir)
                assert sbom.total == 2
                assert sbom.components[0].purl == "pkg:pypi/requests@2.31.0"
                assert sbom.components[1].purl == "pkg:pypi/flask@3.0.0"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestExportCLI:
    """Integration tests for `depcheck export` CLI command."""

    def test_export_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["export", "--help"])
        assert result.exit_code == 0
        assert "SBOM" in result.output or "Software Bill of Materials" in result.output
        assert "--format" in result.output
        assert "cyclonedx" in result.output
        assert "spdx" in result.output

    def test_export_cyclonedx_mocked(self) -> None:
        """Test CycloneDX export with mocked scan."""
        mock_scan_result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
            files_scanned=["/tmp/test/requirements.txt"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("requests==2.31.0\n")

            with patch("depcheck.export.scan_project", return_value=mock_scan_result):
                runner = CliRunner()
                result = runner.invoke(main, ["export", "--format", "cyclonedx", tmpdir])
                assert result.exit_code == 0
                data = json.loads(result.output)
                assert data["bomFormat"] == "CycloneDX"
                assert len(data["components"]) == 1

    def test_export_spdx_mocked(self) -> None:
        """Test SPDX export with mocked scan."""
        mock_scan_result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="flask",
                    installed_version="3.0.0",
                    latest_version="3.0.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
            files_scanned=["/tmp/test/requirements.txt"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("flask==3.0.0\n")

            with patch("depcheck.export.scan_project", return_value=mock_scan_result):
                runner = CliRunner()
                result = runner.invoke(main, ["export", "--format", "spdx", tmpdir])
                assert result.exit_code == 0
                data = json.loads(result.output)
                assert data["spdxVersion"] == "SPDX-2.3"

    def test_export_summary_json(self) -> None:
        """Test summary JSON export."""
        mock_scan_result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
            files_scanned=["/tmp/test/requirements.txt"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("requests==2.31.0\n")

            with patch("depcheck.export.scan_project", return_value=mock_scan_result):
                runner = CliRunner()
                result = runner.invoke(
                    main, ["export", "--format", "summary", "--json-output", tmpdir]
                )
                assert result.exit_code == 0
                data = json.loads(result.output)
                assert data["total_components"] == 1

    def test_export_to_file(self) -> None:
        """Test export to file."""
        mock_scan_result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
            files_scanned=["/tmp/test/requirements.txt"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("requests==2.31.0\n")

            out_path = Path(tmpdir) / "bom.cdx.json"

            with patch("depcheck.export.scan_project", return_value=mock_scan_result):
                runner = CliRunner()
                result = runner.invoke(
                    main,
                    [
                        "export",
                        "--format",
                        "cyclonedx",
                        "--output",
                        str(out_path),
                        tmpdir,
                    ],
                )
                assert result.exit_code == 0
                assert out_path.exists()
                data = json.loads(out_path.read_text())
                assert data["bomFormat"] == "CycloneDX"

    def test_export_quiet(self) -> None:
        """Test export with --quiet flag."""
        mock_scan_result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
            files_scanned=["/tmp/test/requirements.txt"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("requests==2.31.0\n")

            with patch("depcheck.export.scan_project", return_value=mock_scan_result):
                runner = CliRunner()
                result = runner.invoke(main, ["export", "--format", "cyclonedx", "--quiet", tmpdir])
                assert result.exit_code == 0

    def test_export_no_vuln_check(self) -> None:
        """Test export with --no-vuln-check flag."""
        mock_scan_result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
            files_scanned=["/tmp/test/requirements.txt"],
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            req = Path(tmpdir) / "requirements.txt"
            req.write_text("requests==2.31.0\n")

            with patch("depcheck.export.scan_project", return_value=mock_scan_result) as mock_scan:
                runner = CliRunner()
                result = runner.invoke(
                    main, ["export", "--format", "cyclonedx", "--no-vuln-check", tmpdir]
                )
                assert result.exit_code == 0
                # Verify that scan_project was called with check_vulnerabilities=False
                _, kwargs = mock_scan.call_args
                assert kwargs["check_vulnerabilities"] is False

    def test_export_nonexistent_path(self) -> None:
        """Test export with a non-existent path."""
        runner = CliRunner()
        result = runner.invoke(main, ["export", "/nonexistent/path"])
        assert result.exit_code != 0  # Click validates path existence


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_component_with_no_version(self) -> None:
        comp = SBOMComponent(
            name="unpinned-pkg",
            version="unknown",
            health_status=HealthStatus.UNKNOWN,
        )
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=[comp])
        # CycloneDX should still work
        doc = to_cyclonedx(sbom)
        assert len(doc["components"]) == 1

    def test_empty_sbom(self) -> None:
        sbom = SBOMResult(project_path="/tmp/test", format="raw")
        assert sbom.total == 0
        assert sbom.healthy_count == 0
        assert sbom.vulnerable_count == 0

        doc_cdx = to_cyclonedx(sbom)
        assert doc_cdx["components"] == []

        doc_spdx = to_spdx(sbom)
        assert doc_spdx["packages"] == []

    def test_multiple_vulnerabilities_per_component(self) -> None:
        comp = SBOMComponent(
            name="multi-vuln",
            version="1.0.0",
            purl="pkg:pypi/multi-vuln@1.0.0",
            health_status=HealthStatus.VULNERABLE,
            vulnerabilities=[
                _make_vuln("CVE-2023-001", "First", "HIGH"),
                _make_vuln("CVE-2023-002", "Second", "MEDIUM"),
                _make_vuln("CVE-2023-003", "Third", "LOW"),
            ],
        )
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=[comp])
        doc = to_cyclonedx(sbom)
        assert len(doc["vulnerabilities"]) == 3

        # Severity mapping
        high_vuln = next(v for v in doc["vulnerabilities"] if v["id"] == "CVE-2023-001")
        assert high_vuln["ratings"][0]["severity"] == "high"

        medium_vuln = next(v for v in doc["vulnerabilities"] if v["id"] == "CVE-2023-002")
        assert medium_vuln["ratings"][0]["severity"] == "medium"

        low_vuln = next(v for v in doc["vulnerabilities"] if v["id"] == "CVE-2023-003")
        assert low_vuln["ratings"][0]["severity"] == "low"

    def test_summary_with_no_vulns(self) -> None:
        comp = SBOMComponent(
            name="safe-pkg",
            version="1.0.0",
            health_status=HealthStatus.HEALTHY,
        )
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=[comp])
        summary = to_summary(sbom)
        assert summary["vulnerabilities"]["total"] == 0
        assert summary["vulnerabilities"]["high_or_critical"] == 0

    def test_cyclonedx_unknown_severity_vuln(self) -> None:
        comp = SBOMComponent(
            name="pkg",
            version="1.0.0",
            health_status=HealthStatus.VULNERABLE,
            vulnerabilities=[_make_vuln(severity="UNKNOWN")],
        )
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=[comp])
        doc = to_cyclonedx(sbom)
        vuln = doc["vulnerabilities"][0]
        # UNKNOWN severity should result in empty ratings
        assert vuln["ratings"] == []

    def test_all_health_statuses_in_sbom(self) -> None:
        """Test that all health statuses are handled in SBOM output."""
        statuses = [
            HealthStatus.HEALTHY,
            HealthStatus.OUTDATED,
            HealthStatus.VULNERABLE,
            HealthStatus.UNMAINTAINED,
            HealthStatus.YANKED,
            HealthStatus.REMOVED,
            HealthStatus.UNKNOWN,
        ]
        components = [
            SBOMComponent(
                name=f"pkg-{s.value}",
                version="1.0.0",
                health_status=s,
                is_yanked=(s == HealthStatus.YANKED),
                is_removed=(s == HealthStatus.REMOVED),
            )
            for s in statuses
        ]
        sbom = SBOMResult(project_path="/tmp/test", format="raw", components=components)

        # Both formats should work without errors
        doc_cdx = to_cyclonedx(sbom)
        assert len(doc_cdx["components"]) == 7

        doc_spdx = to_spdx(sbom)
        assert len(doc_spdx["packages"]) == 7
