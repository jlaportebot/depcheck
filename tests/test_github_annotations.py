"""Tests for GitHub Actions annotation output format."""

from depcheck.models import (
    HealthStatus,
    LicenseInfo,
    PackageReport,
    ScanResult,
    Vulnerability,
)
from depcheck.output import render_github_annotations


def test_render_github_annotations_vulnerable():
    """Test annotations for vulnerable packages."""
    vuln = Vulnerability(
        vuln_id="GHSA-1234-5678-9012",
        summary="Test vulnerability",
        severity="HIGH",
        url="https://github.com/advisories/GHSA-1234-5678-9012",
    )
    pkg = PackageReport(
        name="vulnerable-pkg",
        installed_version="1.0.0",
        latest_version="2.0.0",
        status=HealthStatus.VULNERABLE,
        vulnerabilities=[vuln],
    )
    result = ScanResult(
        project_path="/test",
        packages=[pkg],
    )

    annotations = render_github_annotations(result)
    assert len(annotations) == 1
    ann = annotations[0]
    assert ann["type"] == "error"
    assert "vulnerable-pkg" in ann["message"]
    assert "GHSA-1234-5678-9012" in ann["message"]
    assert "High" in ann["message"]


def test_render_github_annotations_outdated():
    """Test annotations for outdated packages."""
    pkg = PackageReport(
        name="outdated-pkg",
        installed_version="1.0.0",
        latest_version="2.0.0",
        status=HealthStatus.OUTDATED,
    )
    result = ScanResult(
        project_path="/test",
        packages=[pkg],
    )

    annotations = render_github_annotations(result)
    assert len(annotations) == 1
    ann = annotations[0]
    assert ann["type"] == "warning"
    assert "outdated-pkg" in ann["message"]
    assert "1.0.0" in ann["message"]
    assert "2.0.0" in ann["message"]


def test_render_github_annotations_unmaintained():
    """Test annotations for unmaintained packages."""
    pkg = PackageReport(
        name="unmaintained-pkg",
        installed_version="1.0.0",
        latest_version="1.0.0",
        status=HealthStatus.UNMAINTAINED,
    )
    result = ScanResult(
        project_path="/test",
        packages=[pkg],
    )

    annotations = render_github_annotations(result)
    assert len(annotations) == 1
    ann = annotations[0]
    assert ann["type"] == "warning"
    assert "unmaintained-pkg" in ann["message"]
    assert "unmaintained" in ann["message"].lower()


def test_render_github_annotations_yanked():
    """Test annotations for yanked packages."""
    pkg = PackageReport(
        name="yanked-pkg",
        installed_version="1.0.0",
        latest_version="1.0.0",
        status=HealthStatus.YANKED,
    )
    result = ScanResult(
        project_path="/test",
        packages=[pkg],
    )

    annotations = render_github_annotations(result)
    assert len(annotations) == 1
    ann = annotations[0]
    assert ann["type"] == "error"
    assert "yanked-pkg" in ann["message"]
    assert "yanked" in ann["message"].lower()


def test_render_github_annotations_license_issue():
    """Test annotations for license compliance issues."""
    license_info = LicenseInfo(
        spdx_id="GPL-3.0-only",
        category="copyleft",
        is_compliant=False,
        compliance_note="Copyleft license may not be compatible",
    )
    pkg = PackageReport(
        name="license-issue-pkg",
        installed_version="1.0.0",
        latest_version="1.0.0",
        status=HealthStatus.HEALTHY,
        license_info=license_info,
    )
    result = ScanResult(
        project_path="/test",
        packages=[pkg],
    )

    annotations = render_github_annotations(result)
    assert len(annotations) == 1
    ann = annotations[0]
    assert ann["type"] == "warning"
    assert "license-issue-pkg" in ann["message"]
    assert "license" in ann["message"].lower()


def test_render_github_annotations_healthy_no_annotations():
    """Test that healthy packages produce no annotations."""
    pkg = PackageReport(
        name="healthy-pkg",
        installed_version="1.0.0",
        latest_version="1.0.0",
        status=HealthStatus.HEALTHY,
    )
    result = ScanResult(
        project_path="/test",
        packages=[pkg],
    )

    annotations = render_github_annotations(result)
    assert len(annotations) == 0


def test_render_github_annotations_multiple_vulns():
    """Test multiple vulnerabilities on same package produce separate annotations."""
    vuln1 = Vulnerability(
        vuln_id="GHSA-1111-1111-1111",
        summary="Vuln 1",
        severity="HIGH",
        url="https://example.com/1",
    )
    vuln2 = Vulnerability(
        vuln_id="GHSA-2222-2222-2222",
        summary="Vuln 2",
        severity="MEDIUM",
        url="https://example.com/2",
    )
    pkg = PackageReport(
        name="multi-issue-pkg",
        installed_version="1.0.0",
        latest_version="2.0.0",
        status=HealthStatus.VULNERABLE,
        vulnerabilities=[vuln1, vuln2],
    )
    result = ScanResult(
        project_path="/test",
        packages=[pkg],
    )

    annotations = render_github_annotations(result)
    # Should produce one annotation per vulnerability
    assert len(annotations) == 2
    messages = [a["message"] for a in annotations]
    assert any("GHSA-1111-1111-1111" in m for m in messages)
    assert any("GHSA-2222-2222-2222" in m for m in messages)


def test_render_github_annotations_removed():
    """Test annotations for removed packages."""
    pkg = PackageReport(
        name="removed-pkg",
        installed_version="1.0.0",
        latest_version="1.0.0",
        status=HealthStatus.REMOVED,
    )
    result = ScanResult(
        project_path="/test",
        packages=[pkg],
    )

    annotations = render_github_annotations(result)
    assert len(annotations) == 1
    ann = annotations[0]
    assert ann["type"] == "error"
    assert "removed-pkg" in ann["message"]
    assert "removed" in ann["message"].lower()
