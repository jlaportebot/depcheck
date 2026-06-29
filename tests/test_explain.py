"""Tests for the depcheck.explain module — dependency explanations."""

from __future__ import annotations

import json
from unittest.mock import patch

from depcheck.explain import (
    ExplainReport,
    HealthStatus,
    OutputFormat,
    PackageExplanation,
    explain_package,
    explain_project,
    get_package_info,
    render_explain_ai,
    render_explain_json,
    render_explain_markdown,
    render_explain_plain,
)
from depcheck.models import LicenseInfo, PackageReport, ScanResult, Vulnerability

# ---------------------------------------------------------------------------
# Package knowledge database tests
# ---------------------------------------------------------------------------


class TestGetPackageInfo:
    """Tests for get_package_info."""

    def test_known_package(self):
        info = get_package_info("requests")
        assert info["category"] == "http-client"
        assert "HTTP" in info["description"]

    def test_known_package_case_insensitive(self):
        info = get_package_info("Requests")
        assert info["category"] == "http-client"

    def test_unknown_package(self):
        info = get_package_info("totally-unknown-xyz-12345")
        assert info["category"] == "unknown"
        assert "totally-unknown-xyz-12345" in info["description"]

    def test_hyphen_underscore_normalization(self):
        # pyyaml is in the knowledge base as "pyyaml"
        info = get_package_info("pyyaml")
        assert info["category"] == "configuration"

    def test_numpy(self):
        info = get_package_info("numpy")
        assert info["category"] == "scientific-computing"
        assert "numerical" in info["description"].lower()

    def test_flask(self):
        info = get_package_info("flask")
        assert info["category"] == "web-framework"
        assert "WSGI" in info["description"]

    def test_click(self):
        info = get_package_info("click")
        assert info["category"] == "cli"
        assert "CLI" in info["description"] or "Command" in info["description"]

    def test_pydantic(self):
        info = get_package_info("pydantic")
        assert info["category"] == "data-validation"
        assert "validation" in info["description"].lower()

    def test_django(self):
        info = get_package_info("django")
        assert info["category"] == "web-framework"
        assert "alternatives" in info


# ---------------------------------------------------------------------------
# PackageExplanation model tests
# ---------------------------------------------------------------------------


class TestPackageExplanation:
    """Tests for PackageExplanation model."""

    def test_to_dict(self):
        pe = PackageExplanation(
            name="requests",
            installed_version="2.28.0",
            latest_version="2.31.0",
            status=HealthStatus.OUTDATED,
            category="http-client",
            description="HTTP library",
            ecosystem_role="Direct HTTP client",
            alternatives="httpx, aiohttp",
            is_outdated=True,
        )
        d = pe.to_dict()
        assert d["name"] == "requests"
        assert d["installed_version"] == "2.28.0"
        assert d["latest_version"] == "2.31.0"
        assert d["status"] == "outdated"
        assert d["category"] == "http-client"
        assert d["is_outdated"] is True

    def test_to_dict_vulnerable(self):
        pe = PackageExplanation(
            name="vuln-pkg",
            installed_version="1.0.0",
            status=HealthStatus.VULNERABLE,
            is_vulnerable=True,
            vulnerabilities=[{"id": "CVE-1", "severity": "high"}],
        )
        d = pe.to_dict()
        assert d["is_vulnerable"] is True
        assert len(d["vulnerabilities"]) == 1

    def test_to_dict_with_license(self):
        pe = PackageExplanation(
            name="pkg",
            installed_version="1.0.0",
            has_license_issue=True,
            license_info={"spdx_id": "GPL-3.0", "is_compliant": False},
        )
        d = pe.to_dict()
        assert d["has_license_issue"] is True
        assert d["license_info"]["spdx_id"] == "GPL-3.0"

    def test_action_items(self):
        pe = PackageExplanation(
            name="old-pkg",
            installed_version="1.0.0",
            latest_version="2.0.0",
            is_outdated=True,
            action_items=["Upgrade to 2.0.0", "Run tests after upgrade"],
        )
        d = pe.to_dict()
        assert len(d["action_items"]) == 2


# ---------------------------------------------------------------------------
# ExplainReport model tests
# ---------------------------------------------------------------------------


class TestExplainReport:
    """Tests for ExplainReport model."""

    def test_to_dict(self):
        report = ExplainReport(
            project_path="/tmp/test",
            packages=[
                PackageExplanation(name="pkg1", installed_version="1.0.0"),
                PackageExplanation(name="pkg2", installed_version="2.0.0"),
            ],
            total_packages=2,
            at_risk_count=0,
            healthy_count=2,
        )
        d = report.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert d["total_packages"] == 2
        assert len(d["packages"]) == 2

    def test_empty_report(self):
        report = ExplainReport(project_path="/tmp/empty")
        d = report.to_dict()
        assert d["total_packages"] == 0
        assert d["packages"] == []


# ---------------------------------------------------------------------------
# explain_package tests
# ---------------------------------------------------------------------------


class TestExplainPackage:
    """Tests for explain_package."""

    def test_healthy_package(self):
        pkg = PackageReport(
            name="requests",
            installed_version="2.28.0",
            latest_version="2.28.0",
            status=HealthStatus.HEALTHY,
        )
        explanation = explain_package(pkg)
        assert explanation.name == "requests"
        assert explanation.category == "http-client"
        assert explanation.description != ""
        assert explanation.is_vulnerable is False
        assert explanation.is_outdated is False
        assert explanation.risk_summary == "No known risks"

    def test_vulnerable_package(self):
        vuln = Vulnerability(
            vuln_id="CVE-2024-0001",
            summary="RCE vulnerability",
            severity="critical",
            url="https://example.com",
        )
        pkg = PackageReport(
            name="vuln-pkg",
            installed_version="1.0.0",
            latest_version="2.0.0",
            status=HealthStatus.VULNERABLE,
            vulnerabilities=[vuln],
        )
        explanation = explain_package(pkg)
        assert explanation.is_vulnerable is True
        assert "vulnerabilit" in explanation.risk_summary.lower()
        assert len(explanation.action_items) > 0

    def test_outdated_package(self):
        pkg = PackageReport(
            name="click",
            installed_version="7.0.0",
            latest_version="8.0.0",
            status=HealthStatus.OUTDATED,
        )
        explanation = explain_package(pkg)
        assert explanation.is_outdated is True
        assert (
            "Major version behind" in explanation.risk_summary
            or "outdated" in explanation.risk_summary.lower()
        )

    def test_unmaintained_package(self):
        pkg = PackageReport(
            name="py",
            installed_version="1.11.0",
            status=HealthStatus.UNMAINTAINED,
        )
        explanation = explain_package(pkg)
        assert explanation.is_unmaintained is True
        assert "unmaintained" in explanation.risk_summary.lower()
        # Should suggest alternatives
        assert any(
            "alternative" in a.lower() or "audit" in a.lower() for a in explanation.action_items
        )

    def test_yanked_package(self):
        pkg = PackageReport(
            name="bad-pkg",
            installed_version="1.0.0",
            status=HealthStatus.YANKED,
            is_yanked=True,
        )
        explanation = explain_package(pkg)
        assert "yanked" in explanation.risk_summary.lower()
        assert any("yanked" in a.lower() for a in explanation.action_items)

    def test_removed_package(self):
        pkg = PackageReport(
            name="gone-pkg",
            installed_version="1.0.0",
            status=HealthStatus.REMOVED,
            is_removed=True,
        )
        explanation = explain_package(pkg)
        assert "removed" in explanation.risk_summary.lower()
        assert any(
            "removed" in a.lower() or "alternative" in a.lower() for a in explanation.action_items
        )

    def test_license_issue_package(self):
        pkg = PackageReport(
            name="gpl-pkg",
            installed_version="1.0.0",
            status=HealthStatus.HEALTHY,
            license_info=LicenseInfo(
                spdx_id="GPL-3.0",
                category="copyleft",
                is_compliant=False,
                compliance_note="Copyleft denied by policy",
            ),
        )
        explanation = explain_package(pkg)
        assert explanation.has_license_issue is True
        assert "license" in explanation.risk_summary.lower()
        assert any("license" in a.lower() or "GPL" in a for a in explanation.action_items)

    def test_unknown_package_still_works(self):
        pkg = PackageReport(
            name="my-custom-internal-pkg-12345",
            installed_version="0.1.0",
            status=HealthStatus.HEALTHY,
        )
        explanation = explain_package(pkg)
        assert explanation.name == "my-custom-internal-pkg-12345"
        assert explanation.category == "unknown"


# ---------------------------------------------------------------------------
# explain_project tests (with mocking)
# ---------------------------------------------------------------------------


class TestExplainProject:
    """Tests for explain_project."""

    @patch("depcheck.explain.scan_project")
    def test_basic_project(self, mock_scan):
        mock_scan.return_value = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.28.0",
                    latest_version="2.31.0",
                    status=HealthStatus.OUTDATED,
                ),
                PackageReport(
                    name="click",
                    installed_version="8.0.0",
                    latest_version="8.0.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
        )
        report = explain_project("/tmp/test")
        assert report.total_packages == 2
        assert report.at_risk_count == 1  # requests is outdated
        assert report.healthy_count == 1  # click is healthy

    @patch("depcheck.explain.scan_project")
    def test_empty_project(self, mock_scan):
        mock_scan.return_value = ScanResult(project_path="/tmp/empty", packages=[])
        report = explain_project("/tmp/empty")
        assert report.total_packages == 0

    @patch("depcheck.explain.scan_project")
    def test_with_vulnerabilities(self, mock_scan):
        vuln = Vulnerability(
            vuln_id="CVE-1", summary="RCE", severity="critical", url="https://x.com"
        )
        mock_scan.return_value = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="vuln-pkg",
                    installed_version="1.0.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[vuln],
                ),
            ],
        )
        report = explain_project("/tmp/test")
        assert report.at_risk_count == 1


# ---------------------------------------------------------------------------
# Rendering tests (smoke tests)
# ---------------------------------------------------------------------------


class TestRenderExplainPlain:
    """Tests for render_explain_plain."""

    def test_basic_render(self):
        from io import StringIO

        from rich.console import Console

        report = ExplainReport(
            project_path="/tmp/test",
            packages=[
                PackageExplanation(
                    name="requests",
                    installed_version="2.28.0",
                    latest_version="2.31.0",
                    status=HealthStatus.OUTDATED,
                    category="http-client",
                    description="HTTP library for Python.",
                    ecosystem_role="Direct HTTP client",
                    is_outdated=True,
                    risk_summary="Minor version behind (latest: 2.31.0)",
                    action_items=["Consider upgrading: pip install requests==2.31.0"],
                    alternatives="httpx, aiohttp, urllib3",
                ),
            ],
            total_packages=1,
            healthy_count=0,
            at_risk_count=1,
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True, width=100)
        render_explain_plain(report, console=console)
        output = buf.getvalue()
        assert "requests" in output
        assert "2.28.0" in output
        assert "HTTP" in output

    def test_render_healthy(self):
        from io import StringIO

        from rich.console import Console

        report = ExplainReport(
            project_path="/tmp/test",
            packages=[
                PackageExplanation(
                    name="click",
                    installed_version="8.0.0",
                    status=HealthStatus.HEALTHY,
                    category="cli",
                    description="CLI toolkit.",
                    risk_summary="No known risks",
                ),
            ],
            total_packages=1,
            healthy_count=1,
            at_risk_count=0,
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True, width=100)
        render_explain_plain(report, console=console)
        output = buf.getvalue()
        assert "click" in output
        assert "8.0.0" in output


class TestRenderExplainJson:
    """Tests for render_explain_json."""

    def test_basic_render(self):
        from io import StringIO

        from rich.console import Console

        report = ExplainReport(
            project_path="/tmp/test",
            packages=[
                PackageExplanation(
                    name="requests", installed_version="2.28.0", category="http-client"
                ),
            ],
            total_packages=1,
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_explain_json(report, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert data["total_packages"] == 1
        assert data["packages"][0]["name"] == "requests"


class TestRenderExplainMarkdown:
    """Tests for render_explain_markdown."""

    def test_basic_render(self):
        from io import StringIO

        from rich.console import Console

        report = ExplainReport(
            project_path="/tmp/test",
            packages=[
                PackageExplanation(
                    name="click",
                    installed_version="8.0.0",
                    status=HealthStatus.HEALTHY,
                    category="cli",
                    description="CLI toolkit.",
                    alternatives="argparse, typer",
                ),
                PackageExplanation(
                    name="requests",
                    installed_version="2.28.0",
                    latest_version="2.31.0",
                    status=HealthStatus.OUTDATED,
                    category="http-client",
                    description="HTTP library.",
                    is_outdated=True,
                    risk_summary="Outdated (latest: 2.31.0)",
                    action_items=["Consider upgrading"],
                ),
            ],
            total_packages=2,
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True, width=120)
        render_explain_markdown(report, console=console)
        output = buf.getvalue()
        assert "click" in output or "CLI" in output

    def test_render_with_action_items(self):
        from io import StringIO

        from rich.console import Console

        report = ExplainReport(
            project_path="/tmp/test",
            packages=[
                PackageExplanation(
                    name="vuln-pkg",
                    installed_version="1.0.0",
                    status=HealthStatus.VULNERABLE,
                    category="unknown",
                    is_vulnerable=True,
                    risk_summary="Has known vulnerabilities",
                    action_items=["Upgrade immediately", "  → pip install vuln-pkg==2.0.0"],
                ),
            ],
            total_packages=1,
            at_risk_count=1,
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True, width=120)
        render_explain_markdown(report, console=console)
        output = buf.getvalue()
        # Markdown should contain the package name or action items
        assert len(output) > 0


class TestRenderExplainAi:
    """Tests for render_explain_ai."""

    def test_basic_render(self):
        from io import StringIO

        from rich.console import Console

        report = ExplainReport(
            project_path="/tmp/test",
            packages=[
                PackageExplanation(
                    name="requests",
                    installed_version="2.28.0",
                    latest_version="2.31.0",
                    status=HealthStatus.OUTDATED,
                    category="http-client",
                    description="HTTP library for Python.",
                    is_outdated=True,
                ),
            ],
            total_packages=1,
            at_risk_count=1,
            healthy_count=0,
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_explain_ai(report, console=console)
        output = buf.getvalue()
        assert "DEPS" in output
        assert "requests" in output
        assert "OUTDATED" in output

    def test_compact_format(self):
        from io import StringIO

        from rich.console import Console

        report = ExplainReport(
            project_path="/tmp/test",
            packages=[
                PackageExplanation(
                    name="click",
                    installed_version="8.0.0",
                    status=HealthStatus.HEALTHY,
                    category="cli",
                ),
            ],
            total_packages=1,
            healthy_count=1,
            at_risk_count=0,
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_explain_ai(report, console=console)
        output = buf.getvalue()
        # AI format should have PKG lines
        assert "PKG" in output


# ---------------------------------------------------------------------------
# OutputFormat enum tests
# ---------------------------------------------------------------------------


class TestOutputFormat:
    """Tests for OutputFormat enum."""

    def test_values(self):
        assert OutputFormat.PLAIN.value == "plain"
        assert OutputFormat.MARKDOWN.value == "markdown"
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.AI.value == "ai"

    def test_from_string(self):
        assert OutputFormat("plain") == OutputFormat.PLAIN
        assert OutputFormat("json") == OutputFormat.JSON
