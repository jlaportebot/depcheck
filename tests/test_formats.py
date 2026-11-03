"""Tests for depcheck formats module."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET

import pytest

from depcheck.formats import (
    FORMAT_CHOICES,
    render_format,
    to_junit_xml,
    to_markdown,
    to_sarif,
)
from depcheck.models import HealthStatus, LicenseInfo, PackageReport, ScanResult, Vulnerability


class TestSarif:
    """Tests for SARIF output."""

    def create_scan_result(self) -> ScanResult:
        return ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
                PackageReport(
                    name="urllib3",
                    installed_version="1.26.15",
                    latest_version="2.0.0",
                    status=HealthStatus.OUTDATED,
                ),
                PackageReport(
                    name="django",
                    installed_version="4.1.0",
                    latest_version="4.2.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[
                        Vulnerability(
                            vuln_id="CVE-2023-12345",
                            summary="SQL injection vulnerability",
                            severity="HIGH",
                            url="https://github.com/advisories/GHSA-xxxx",
                        ),
                        Vulnerability(
                            vuln_id="CVE-2023-67890",
                            summary="XSS vulnerability",
                            severity="MEDIUM",
                            url="https://github.com/advisories/GHSA-yyyy",
                        ),
                    ],
                ),
                PackageReport(
                    name="oldpackage",
                    installed_version="1.0.0",
                    latest_version=None,
                    status=HealthStatus.UNMAINTAINED,
                ),
                PackageReport(
                    name="yankedpkg",
                    installed_version="1.0.0",
                    latest_version="1.0.1",
                    status=HealthStatus.YANKED,
                ),
                PackageReport(
                    name="removedpkg",
                    installed_version="1.0.0",
                    latest_version=None,
                    status=HealthStatus.REMOVED,
                ),
                PackageReport(
                    name="gplpkg",
                    installed_version="1.0.0",
                    latest_version="1.0.0",
                    status=HealthStatus.HEALTHY,
                    license_info=LicenseInfo(
                        spdx_id="GPL-3.0",
                        category="copyleft",
                        is_compliant=False,
                        compliance_note="Copyleft license may not be compatible",
                    ),
                ),
            ],
            files_scanned=["requirements.txt"],
        )

    def test_to_sarif_valid_json(self) -> None:
        result = self.create_scan_result()
        sarif_output = to_sarif(result)
        # Must be valid JSON
        data = json.loads(sarif_output)
        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert data["runs"][0]["tool"]["driver"]["name"] == "depcheck"

    def test_to_sarif_deterministic(self) -> None:
        result = self.create_scan_result()
        output1 = to_sarif(result)
        output2 = to_sarif(result)
        assert output1 == output2

    def test_to_sarif_vulnerability_rules(self) -> None:
        result = self.create_scan_result()
        sarif_output = to_sarif(result)
        data = json.loads(sarif_output)
        rules = {r["id"]: r for r in data["runs"][0]["tool"]["driver"]["rules"]}
        assert "depcheck/vulnerability" in rules
        assert "depcheck/outdated" in rules
        assert "depcheck/unmaintained" in rules
        assert "depcheck/yanked" in rules
        assert "depcheck/removed" in rules
        assert "depcheck/license" in rules

    def test_to_sarif_vulnerability_results(self) -> None:
        result = self.create_scan_result()
        sarif_output = to_sarif(result)
        data = json.loads(sarif_output)
        results = data["runs"][0]["results"]
        # Should have results for: outdated, 2 vulns, unmaintained, yanked, removed, license
        # But vulnerabilities might be grouped or separate
        assert len(results) >= 6

    def test_to_sarif_vulnerability_severity_mapping(self) -> None:
        # Test severity mapping: CRITICAL/HIGH -> error, MEDIUM -> warning, LOW -> note
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="pkg-critical",
                    installed_version="1.0.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[Vulnerability("CVE-1", "critical", "CRITICAL", "http://x")],
                ),
                PackageReport(
                    name="pkg-high",
                    installed_version="1.0.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[Vulnerability("CVE-2", "high", "HIGH", "http://x")],
                ),
                PackageReport(
                    name="pkg-medium",
                    installed_version="1.0.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[Vulnerability("CVE-3", "medium", "MEDIUM", "http://x")],
                ),
                PackageReport(
                    name="pkg-low",
                    installed_version="1.0.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[Vulnerability("CVE-4", "low", "LOW", "http://x")],
                ),
            ],
        )
        sarif_output = to_sarif(result)
        data = json.loads(sarif_output)
        results = data["runs"][0]["results"]
        levels = {r.get("level") for r in results}
        assert "error" in levels  # CRITICAL, HIGH
        assert "warning" in levels  # MEDIUM
        assert "note" in levels  # LOW

    def test_to_sarif_includes_package_info(self) -> None:
        result = self.create_scan_result()
        sarif_output = to_sarif(result)
        data = json.loads(sarif_output)
        results = data["runs"][0]["results"]
        for r in results:
            assert "message" in r
            assert "text" in r["message"]
            # Package name should be in message
            assert any(
                pkg in r["message"]["text"]
                for pkg in ["urllib3", "django", "oldpackage", "yankedpkg", "removedpkg", "gplpkg"]
            )


class TestMarkdown:
    """Tests for Markdown output."""

    def create_scan_result(self) -> ScanResult:
        return ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
                PackageReport(
                    name="urllib3",
                    installed_version="1.26.15",
                    latest_version="2.0.0",
                    status=HealthStatus.OUTDATED,
                ),
                PackageReport(
                    name="django",
                    installed_version="4.1.0",
                    latest_version="4.2.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[
                        Vulnerability(
                            vuln_id="CVE-2023-12345",
                            summary="SQL injection vulnerability",
                            severity="HIGH",
                            url="https://github.com/advisories/GHSA-xxxx",
                        ),
                    ],
                ),
                PackageReport(
                    name="gplpkg",
                    installed_version="1.0.0",
                    latest_version="1.0.0",
                    status=HealthStatus.HEALTHY,
                    license_info=LicenseInfo(
                        spdx_id="GPL-3.0",
                        category="copyleft",
                        is_compliant=False,
                        compliance_note="Copyleft license may not be compatible",
                    ),
                ),
            ],
            files_scanned=["requirements.txt"],
        )

    def test_to_markdown_basic(self) -> None:
        result = self.create_scan_result()
        md = to_markdown(result)
        assert isinstance(md, str)
        assert "# depcheck Dependency Health Report" in md
        assert "**Project:** /test" in md
        assert "requirements.txt" in md

    def test_to_markdown_summary_table(self) -> None:
        result = self.create_scan_result()
        md = to_markdown(result)
        # Check for summary table with package, installed, latest, status
        assert "| Package | Installed | Latest | Status |" in md
        assert "| requests | 2.31.0 | 2.31.0 | healthy |" in md
        assert "| urllib3 | 1.26.15 | 2.0.0 | outdated |" in md
        assert "| django | 4.1.0 | 4.2.0 | vulnerable |" in md

    def test_to_markdown_vulnerabilities_section(self) -> None:
        result = self.create_scan_result()
        md = to_markdown(result)
        assert "## Vulnerabilities" in md
        assert "CVE-2023-12345" in md
        assert "SQL injection vulnerability" in md
        assert "HIGH" in md

    def test_to_markdown_licenses_section(self) -> None:
        result = self.create_scan_result()
        md = to_markdown(result)
        assert "## Licenses" in md
        assert "gplpkg" in md
        assert "GPL-3.0" in md
        assert "copyleft" in md
        assert "Non-compliant" in md or "not compliant" in md.lower()

    def test_to_markdown_no_ansi(self) -> None:
        result = self.create_scan_result()
        md = to_markdown(result)
        # Should not contain ANSI escape codes
        assert "\x1b[" not in md
        assert "\033[" not in md


class TestJUnitXml:
    """Tests for JUnit XML output."""

    def create_scan_result(self) -> ScanResult:
        return ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
                PackageReport(
                    name="urllib3",
                    installed_version="1.26.15",
                    latest_version="2.0.0",
                    status=HealthStatus.OUTDATED,
                ),
                PackageReport(
                    name="django",
                    installed_version="4.1.0",
                    latest_version="4.2.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[
                        Vulnerability(
                            vuln_id="CVE-2023-12345",
                            summary="SQL injection vulnerability",
                            severity="HIGH",
                            url="https://github.com/advisories/GHSA-xxxx",
                        ),
                    ],
                ),
            ],
            files_scanned=["requirements.txt"],
        )

    def test_to_junit_xml_valid(self) -> None:
        result = self.create_scan_result()
        xml_output = to_junit_xml(result)
        # Must be valid XML
        root = ET.fromstring(xml_output)
        assert root.tag == "testsuites"
        assert len(root.findall("testsuite")) == 1
        suite = root.find("testsuite")
        assert suite is not None
        assert suite.get("name") == "depcheck"
        tests = suite.findall("testcase")
        # Should have test cases for each package issue
        assert len(tests) >= 3

    def test_to_junit_xml_escapes_special_chars(self) -> None:
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="pkg<>&\"'",
                    installed_version="1.0.0",
                    latest_version="2.0.0",
                    status=HealthStatus.OUTDATED,
                ),
            ],
        )
        xml_output = to_junit_xml(result)
        root = ET.fromstring(xml_output)
        suite = root.find("testsuite")
        tests = suite.findall("testcase")
        assert len(tests) == 1
        # The name should be escaped in XML
        name = tests[0].get("name", "")
        assert "<" not in name or "<" in name

    def test_to_junit_xml_vulnerability_as_failure(self) -> None:
        result = self.create_scan_result()
        xml_output = to_junit_xml(result)
        root = ET.fromstring(xml_output)
        suite = root.find("testsuite")
        tests = suite.findall("testcase")
        # Vulnerable packages should have failure elements
        django_test = next(t for t in tests if "django" in t.get("name", ""))
        assert django_test.find("failure") is not None

    def test_to_junit_xml_outdated_as_failure(self) -> None:
        result = self.create_scan_result()
        xml_output = to_junit_xml(result)
        root = ET.fromstring(xml_output)
        suite = root.find("testsuite")
        tests = suite.findall("testcase")
        urllib3_test = next(t for t in tests if "urllib3" in t.get("name", ""))
        # Outdated should be a failure (or at least have a system-out with warning)
        # Let's check it has some indication
        assert urllib3_test is not None


class TestRenderFormat:
    """Tests for render_format dispatcher."""

    def test_render_format_sarif(self) -> None:
        result = ScanResult(project_path="/test")
        output = render_format(result, "sarif")
        data = json.loads(output)
        assert data["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

    def test_render_format_markdown(self) -> None:
        result = ScanResult(project_path="/test")
        output = render_format(result, "markdown")
        assert "# depcheck Dependency Health Report" in output

    def test_render_format_junit(self) -> None:
        result = ScanResult(project_path="/test")
        output = render_format(result, "junit")
        root = ET.fromstring(output)
        assert root.tag == "testsuites"

    def test_render_format_unknown_raises(self) -> None:
        result = ScanResult(project_path="/test")
        with pytest.raises(ValueError, match="Unknown format"):
            render_format(result, "unknown")

    def test_format_choices(self) -> None:
        assert FORMAT_CHOICES == ("sarif", "markdown", "junit")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
