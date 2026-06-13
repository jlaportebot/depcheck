"""Tests for depcheck output module."""

from __future__ import annotations

from io import StringIO

import pytest
from rich.console import Console

from depcheck.models import (
    HealthStatus,
    LicenseInfo,
    PackageReport,
    ScanResult,
    Vulnerability,
)
from depcheck.output import (
    _license_category_style,
    _status_color,
    _status_icon,
    determine_exit_code,
    render_json,
    render_table,
)


class TestStatusIcon:
    """Tests for _status_icon function."""

    def test_healthy(self):
        assert _status_icon(HealthStatus.HEALTHY) == "🟢"

    def test_outdated(self):
        assert _status_icon(HealthStatus.OUTDATED) == "🟡"

    def test_vulnerable(self):
        assert _status_icon(HealthStatus.VULNERABLE) == "🔴"

    def test_unmaintained(self):
        assert _status_icon(HealthStatus.UNMAINTAINED) == "🟡"

    def test_yanked(self):
        assert _status_icon(HealthStatus.YANKED) == "🔴"

    def test_removed(self):
        assert _status_icon(HealthStatus.REMOVED) == "🔴"

    def test_unknown(self):
        assert _status_icon(HealthStatus.UNKNOWN) == "⚪"

    def test_default_fallback(self):
        # Test with a value not in the enum (edge case)
        class FakeStatus:
            pass
        # This should fall back to default
        assert _status_icon(FakeStatus()) == "⚪"


class TestStatusColor:
    """Tests for _status_color function."""

    def test_healthy(self):
        assert _status_color(HealthStatus.HEALTHY) == "green"

    def test_outdated(self):
        assert _status_color(HealthStatus.OUTDATED) == "yellow"

    def test_vulnerable(self):
        assert _status_color(HealthStatus.VULNERABLE) == "red"

    def test_unmaintained(self):
        assert _status_color(HealthStatus.UNMAINTAINED) == "yellow"

    def test_yanked(self):
        assert _status_color(HealthStatus.YANKED) == "red"

    def test_removed(self):
        assert _status_color(HealthStatus.REMOVED) == "red"

    def test_unknown(self):
        assert _status_color(HealthStatus.UNKNOWN) == "white"


class TestLicenseCategoryStyle:
    """Tests for _license_category_style function."""

    def test_permissive(self):
        assert _license_category_style("permissive") == ("✅", "green")

    def test_copyleft(self):
        assert _license_category_style("copyleft") == ("⚠️", "yellow")

    def test_public_domain(self):
        assert _license_category_style("public_domain") == ("✅", "green")

    def test_restricted(self):
        assert _license_category_style("restricted") == ("🚫", "red")

    def test_proprietary(self):
        assert _license_category_style("proprietary") == ("🚫", "red")

    def test_unknown(self):
        assert _license_category_style("unknown") == ("❓", "white")

    def test_custom_unknown(self):
        assert _license_category_style("custom_category") == ("❓", "white")


class TestRenderTable:
    """Tests for render_table function."""

    def create_mock_console(self) -> Console:
        """Create a console that captures output without ANSI codes."""
        return Console(file=StringIO(), force_terminal=False, no_color=True, width=120)

    def create_healthy_package(self, name: str = "requests") -> PackageReport:
        return PackageReport(
            name=name,
            installed_version="2.31.0",
            latest_version="2.31.0",
            status=HealthStatus.HEALTHY,
        )

    def create_outdated_package(self, name: str = "urllib3") -> PackageReport:
        return PackageReport(
            name=name,
            installed_version="1.26.15",
            latest_version="2.0.0",
            status=HealthStatus.OUTDATED,
        )

    def create_vulnerable_package(self, name: str = "django") -> PackageReport:
        return PackageReport(
            name=name,
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
        )

    def create_unmaintained_package(self, name: str = "oldpackage") -> PackageReport:
        return PackageReport(
            name=name,
            installed_version="1.0.0",
            latest_version=None,
            status=HealthStatus.UNMAINTAINED,
        )

    def create_yanked_package(self, name: str = "yankedpkg") -> PackageReport:
        return PackageReport(
            name=name,
            installed_version="1.0.0",
            latest_version="1.0.1",
            status=HealthStatus.YANKED,
        )

    def create_removed_package(self, name: str = "removedpkg") -> PackageReport:
        return PackageReport(
            name=name,
            installed_version="1.0.0",
            latest_version=None,
            status=HealthStatus.REMOVED,
        )

    def create_unknown_package(
        self, name: str = "unknownpkg", error: str = "Failed to fetch"
    ) -> PackageReport:
        return PackageReport(
            name=name,
            installed_version="1.0.0",
            latest_version=None,
            status=HealthStatus.UNKNOWN,
            error=error,
        )

    def create_package_with_license_issue(self, name: str = "gplpkg") -> PackageReport:
        return PackageReport(
            name=name,
            installed_version="1.0.0",
            latest_version="1.0.0",
            status=HealthStatus.HEALTHY,
            license_info=LicenseInfo(
                spdx_id="GPL-3.0",
                category="copyleft",
                is_compliant=False,
                compliance_note="Copyleft license may not be compatible",
            ),
        )

    def test_render_table_empty_result(self):
        console = self.create_mock_console()
        result = ScanResult(project_path="/test", packages=[], files_scanned=[])
        render_table(result, console)
        output = console.file.getvalue()
        assert "depcheck" in output
        assert "Dependency Health Report" in output

    def test_render_table_with_errors_only(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[],
            errors=["Failed to parse requirements"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "Error:" in output
        assert "Failed to parse requirements" in output

    def test_render_table_healthy_packages(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[
                self.create_healthy_package("requests"),
                self.create_healthy_package("urllib3"),
            ],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "requests" in output
        assert "urllib3" in output
        assert "🟢" in output
        assert "OK" in output

    def test_render_table_outdated_packages(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[self.create_outdated_package("urllib3")],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "urllib3" in output
        assert "🟡" in output
        assert "Newer version available" in output

    def test_render_table_vulnerable_packages(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[self.create_vulnerable_package("django")],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "django" in output
        assert "🔴" in output
        assert "CVE-2023-12345" in output
        assert "SQL injection vulnerability" in output
        assert "HIGH" in output
        # Should also show vulnerability details table
        assert "Vulnerability Details" in output

    def test_render_table_unmaintained_packages(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[self.create_unmaintained_package("oldpackage")],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "oldpackage" in output
        assert "🟡" in output
        assert "No updates in 1+ year" in output

    def test_render_table_yanked_packages(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[self.create_yanked_package("yankedpkg")],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "yankedpkg" in output
        assert "🔴" in output
        assert "Version yanked from PyPI" in output

    def test_render_table_removed_packages(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[self.create_removed_package("removedpkg")],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "removedpkg" in output
        assert "🔴" in output
        assert "Package removed from PyPI" in output

    def test_render_table_unknown_packages(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[self.create_unknown_package("unknownpkg", "Network timeout")],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "unknownpkg" in output
        assert "⚪" in output
        assert "Network timeout" in output

    def test_render_table_with_license_issues(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[self.create_package_with_license_issue("gplpkg")],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "gplpkg" in output
        assert "License" in output
        assert "GPL-3.0" in output
        assert "Non-compliant" in output
        assert "License Summary" in output

    def test_render_table_mixed_statuses(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[
                self.create_healthy_package("requests"),
                self.create_outdated_package("urllib3"),
                self.create_vulnerable_package("django"),
            ],
            files_scanned=["requirements.txt"],
        )
        render_table(result, console)
        output = console.file.getvalue()
        assert "requests" in output
        assert "urllib3" in output
        assert "django" in output
        assert "Total: 3 packages" in output
        assert "Healthy: 1" in output
        assert "Outdated: 1" in output
        assert "Vulnerable: 1" in output


class TestRenderJson:
    """Tests for render_json function."""

    def create_mock_console(self) -> Console:
        return Console(file=StringIO(), force_terminal=False, no_color=True, width=120)

    def test_render_json_basic(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                )
            ],
            files_scanned=["requirements.txt"],
        )
        render_json(result, console)
        output = console.file.getvalue()
        # The output uses print_json which adds ANSI colors even with no_color
        # Just verify key content is present
        assert "project_path" in output
        assert "/test" in output
        assert "requests" in output
        assert "healthy" in output

    def test_render_json_with_vulnerabilities(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="django",
                    installed_version="4.1.0",
                    latest_version="4.2.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[
                        Vulnerability(
                            vuln_id="CVE-2023-12345",
                            summary="Test vulnerability",
                            severity="HIGH",
                            url="https://example.com",
                        )
                    ],
                )
            ],
        )
        render_json(result, console)
        output = console.file.getvalue()
        assert "django" in output
        assert "CVE-2023-12345" in output
        assert "HIGH" in output
        assert "vulnerable" in output.lower()

    def test_render_json_with_license_info(self):
        console = self.create_mock_console()
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="gplpkg",
                    installed_version="1.0.0",
                    latest_version="1.0.0",
                    status=HealthStatus.HEALTHY,
                    license_info=LicenseInfo(
                        spdx_id="GPL-3.0",
                        category="copyleft",
                        is_compliant=False,
                        compliance_note="Test note",
                    ),
                )
            ],
        )
        render_json(result, console)
        output = console.file.getvalue()
        assert "gplpkg" in output
        assert "GPL-3.0" in output
        assert "license_issues" in output or "license" in output.lower()


class TestDetermineExitCode:
    """Tests for determine_exit_code function."""

    def test_no_packages_errors_only(self):
        result = ScanResult(project_path="/test", packages=[], errors=["Parse error"])
        assert determine_exit_code(result) == 2

    def test_fail_on_none(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.VULNERABLE)
            ],
        )
        assert determine_exit_code(result, fail_on=None) == 0

    def test_fail_on_vulnerable_true(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.VULNERABLE)
            ],
        )
        assert determine_exit_code(result, fail_on="vulnerable") == 1

    def test_fail_on_vulnerable_false(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.HEALTHY)
            ],
        )
        assert determine_exit_code(result, fail_on="vulnerable") == 0

    def test_fail_on_outdated_true(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.OUTDATED)
            ],
        )
        assert determine_exit_code(result, fail_on="outdated") == 1

    def test_fail_on_outdated_false(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.HEALTHY)
            ],
        )
        assert determine_exit_code(result, fail_on="outdated") == 0

    def test_fail_on_unmaintained_true(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.UNMAINTAINED)
            ],
        )
        assert determine_exit_code(result, fail_on="unmaintained") == 1

    def test_fail_on_unmaintained_false(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.HEALTHY)
            ],
        )
        assert determine_exit_code(result, fail_on="unmaintained") == 0

    def test_fail_on_license_true(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="pkg",
                    installed_version="1.0",
                    status=HealthStatus.HEALTHY,
                    license_info=LicenseInfo(spdx_id="GPL-3.0", is_compliant=False),
                )
            ],
        )
        assert determine_exit_code(result, fail_on="license") == 1

    def test_fail_on_license_false(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="pkg",
                    installed_version="1.0",
                    status=HealthStatus.HEALTHY,
                    license_info=LicenseInfo(spdx_id="MIT", is_compliant=True),
                )
            ],
        )
        assert determine_exit_code(result, fail_on="license") == 0

    def test_fail_on_any_true_vulnerable(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.VULNERABLE)
            ],
        )
        assert determine_exit_code(result, fail_on="any") == 1

    def test_fail_on_any_true_outdated(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.OUTDATED)
            ],
        )
        assert determine_exit_code(result, fail_on="any") == 1

    def test_fail_on_any_true_license(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(
                    name="pkg",
                    installed_version="1.0",
                    status=HealthStatus.HEALTHY,
                    license_info=LicenseInfo(spdx_id="GPL-3.0", is_compliant=False),
                )
            ],
        )
        assert determine_exit_code(result, fail_on="any") == 1

    def test_fail_on_any_false(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.HEALTHY)
            ],
        )
        assert determine_exit_code(result, fail_on="any") == 0

    def test_fail_on_all_true(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.OUTDATED)
            ],
        )
        assert determine_exit_code(result, fail_on="all") == 1

    def test_fail_on_all_false(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.HEALTHY)
            ],
        )
        assert determine_exit_code(result, fail_on="all") == 0

    def test_fail_on_case_insensitive(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.VULNERABLE)
            ],
        )
        assert determine_exit_code(result, fail_on="VULNERABLE") == 1
        assert determine_exit_code(result, fail_on="Vulnerable") == 1

    def test_fail_on_whitespace(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.VULNERABLE)
            ],
        )
        assert determine_exit_code(result, fail_on=" vulnerable ") == 1

    def test_fail_on_unknown_criteria(self):
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.VULNERABLE)
            ],
        )
        # Unknown criteria should return 0 (pass)
        assert determine_exit_code(result, fail_on="unknown") == 0

    def test_errors_with_packages(self):
        # Errors with packages should not return 2
        result = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="pkg", installed_version="1.0", status=HealthStatus.HEALTHY)
            ],
            errors=["Warning: something"],
        )
        assert determine_exit_code(result, fail_on=None) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
