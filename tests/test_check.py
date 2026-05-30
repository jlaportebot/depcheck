"""Tests for the depcheck.check module — comprehensive health check."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depcheck.check import (
    CategoryScore,
    DependencyFreshness,
    Grade,
    HealthReport,
    HealthStatus,
    MaintainerSignal,
    PackageReport,
    ScanResult,
    TransitiveDepth,
    _score_freshness,
    _score_license,
    _score_maintenance,
    _score_outdated,
    _score_transitive_depth,
    _score_vulnerability,
    analyze_freshness,
    analyze_maintainer_signals,
    analyze_transitive_depth,
    render_check_json,
    render_check_table,
    run_check,
)
from depcheck.models import LicenseInfo, Vulnerability


# ---------------------------------------------------------------------------
# Grade tests
# ---------------------------------------------------------------------------


class TestGrade:
    """Tests for Grade enum and from_score conversion."""

    def test_from_score_a(self):
        assert Grade.from_score(100) == Grade.A
        assert Grade.from_score(90) == Grade.A
        assert Grade.from_score(95.5) == Grade.A

    def test_from_score_b(self):
        assert Grade.from_score(89.9) == Grade.B
        assert Grade.from_score(75) == Grade.B
        assert Grade.from_score(80) == Grade.B

    def test_from_score_c(self):
        assert Grade.from_score(74.9) == Grade.C
        assert Grade.from_score(55) == Grade.C
        assert Grade.from_score(60) == Grade.C

    def test_from_score_d(self):
        assert Grade.from_score(54.9) == Grade.D
        assert Grade.from_score(35) == Grade.D
        assert Grade.from_score(40) == Grade.D

    def test_from_score_f(self):
        assert Grade.from_score(34.9) == Grade.F
        assert Grade.from_score(0) == Grade.F
        assert Grade.from_score(10) == Grade.F

    def test_grade_values(self):
        assert Grade.A.value == "A"
        assert Grade.F.value == "F"


# ---------------------------------------------------------------------------
# Vulnerability scoring tests
# ---------------------------------------------------------------------------


class TestScoreVulnerability:
    """Tests for _score_vulnerability."""

    def _make_scan_result(self, packages=None):
        return ScanResult(project_path=".", packages=packages or [])

    def test_no_vulnerabilities(self):
        result = self._make_scan_result([
            PackageReport(name="safe-pkg", installed_version="1.0.0", status=HealthStatus.HEALTHY),
        ])
        score = _score_vulnerability(result)
        assert score.score == 100.0
        assert score.grade == Grade.A

    def test_critical_vulnerability(self):
        vuln = Vulnerability(vuln_id="CVE-2024-0001", summary="RCE", severity="critical", url="https://example.com")
        result = self._make_scan_result([
            PackageReport(
                name="vuln-pkg",
                installed_version="1.0.0",
                status=HealthStatus.VULNERABLE,
                vulnerabilities=[vuln],
            ),
        ])
        score = _score_vulnerability(result)
        assert score.score == 70.0  # 100 - 30
        assert score.grade == Grade.C

    def test_high_vulnerability(self):
        vuln = Vulnerability(vuln_id="CVE-2024-0002", summary="XSS", severity="high", url="https://example.com")
        result = self._make_scan_result([
            PackageReport(
                name="vuln-pkg",
                installed_version="1.0.0",
                status=HealthStatus.VULNERABLE,
                vulnerabilities=[vuln],
            ),
        ])
        score = _score_vulnerability(result)
        assert score.score == 85.0  # 100 - 15

    def test_medium_vulnerability(self):
        vuln = Vulnerability(vuln_id="CVE-2024-0003", summary="Info leak", severity="medium", url="https://example.com")
        result = self._make_scan_result([
            PackageReport(
                name="vuln-pkg",
                installed_version="1.0.0",
                status=HealthStatus.VULNERABLE,
                vulnerabilities=[vuln],
            ),
        ])
        score = _score_vulnerability(result)
        assert score.score == 92.0  # 100 - 8

    def test_low_vulnerability(self):
        vuln = Vulnerability(vuln_id="CVE-2024-0004", summary="Minor", severity="low", url="https://example.com")
        result = self._make_scan_result([
            PackageReport(
                name="vuln-pkg",
                installed_version="1.0.0",
                status=HealthStatus.VULNERABLE,
                vulnerabilities=[vuln],
            ),
        ])
        score = _score_vulnerability(result)
        assert score.score == 97.0  # 100 - 3

    def test_multiple_vulnerabilities(self):
        vulns = [
            Vulnerability(vuln_id=f"CVE-{i}", summary=f"Vuln {i}", severity=s, url="https://example.com")
            for i, s in enumerate(["critical", "high", "medium", "low"])
        ]
        result = self._make_scan_result([
            PackageReport(
                name="multi-vuln",
                installed_version="1.0.0",
                status=HealthStatus.VULNERABLE,
                vulnerabilities=vulns,
            ),
        ])
        score = _score_vulnerability(result)
        assert score.score == 44.0  # 100 - 30 - 15 - 8 - 3

    def test_score_never_below_zero(self):
        vulns = [
            Vulnerability(vuln_id=f"CVE-{i}", summary="RCE", severity="critical", url="https://example.com")
            for i in range(10)
        ]
        result = self._make_scan_result([
            PackageReport(
                name="many-vulns",
                installed_version="1.0.0",
                status=HealthStatus.VULNERABLE,
                vulnerabilities=vulns,
            ),
        ])
        score = _score_vulnerability(result)
        assert score.score == 0.0

    def test_empty_scan(self):
        result = self._make_scan_result()
        score = _score_vulnerability(result)
        assert score.score == 100.0


# ---------------------------------------------------------------------------
# Freshness scoring tests
# ---------------------------------------------------------------------------


class TestScoreFreshness:
    """Tests for _score_freshness."""

    def _make_scan_result(self, packages=None):
        return ScanResult(project_path=".", packages=packages or [])

    def test_no_freshness_data(self):
        result = self._make_scan_result()
        score = _score_freshness(result, [])
        assert score.score == 100.0
        assert score.grade == Grade.A

    def test_all_current(self):
        freshness = [
            DependencyFreshness(name="pkg1", installed_version="1.0.0", latest_version="1.0.0",
                                days_behind=0, freshness_ratio=1.0),
            DependencyFreshness(name="pkg2", installed_version="2.0.0", latest_version="2.0.0",
                                days_behind=0, freshness_ratio=1.0),
        ]
        result = self._make_scan_result()
        score = _score_freshness(result, freshness)
        assert score.score == 100.0

    def test_stale_package(self):
        freshness = [
            DependencyFreshness(name="old-pkg", installed_version="1.0.0", latest_version="2.0.0",
                                days_behind=365, freshness_ratio=0.0),
        ]
        result = self._make_scan_result()
        score = _score_freshness(result, freshness)
        assert score.score == 0.0
        assert score.grade == Grade.F

    def test_mixed_freshness(self):
        freshness = [
            DependencyFreshness(name="fresh", installed_version="1.0.0", latest_version="1.0.0",
                                days_behind=0, freshness_ratio=1.0),
            DependencyFreshness(name="stale", installed_version="1.0.0", latest_version="2.0.0",
                                days_behind=180, freshness_ratio=0.507),
        ]
        result = self._make_scan_result()
        score = _score_freshness(result, freshness)
        assert 50.0 < score.score < 100.0


# ---------------------------------------------------------------------------
# License scoring tests
# ---------------------------------------------------------------------------


class TestScoreLicense:
    """Tests for _score_license."""

    def test_all_compliant(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(
                name="good-pkg",
                installed_version="1.0.0",
                license_info=LicenseInfo(spdx_id="MIT", category="permissive", is_compliant=True),
            ),
        ])
        score = _score_license(result)
        assert score.score == 100.0
        assert score.grade == Grade.A

    def test_non_compliant(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(
                name="bad-pkg",
                installed_version="1.0.0",
                license_info=LicenseInfo(
                    spdx_id="GPL-3.0",
                    category="copyleft",
                    is_compliant=False,
                    compliance_note="Copyleft denied by policy",
                ),
            ),
        ])
        score = _score_license(result)
        assert score.score == 85.0  # 100 - 15

    def test_multiple_non_compliant(self):
        pkgs = [
            PackageReport(
                name=f"pkg{i}",
                installed_version="1.0.0",
                license_info=LicenseInfo(spdx_id="GPL-3.0", category="copyleft", is_compliant=False),
            )
            for i in range(5)
        ]
        result = ScanResult(project_path=".", packages=pkgs)
        score = _score_license(result)
        assert score.score == 25.0  # 100 - 5*15

    def test_empty_packages(self):
        result = ScanResult(project_path=".", packages=[])
        score = _score_license(result)
        assert score.score == 100.0


# ---------------------------------------------------------------------------
# Maintenance scoring tests
# ---------------------------------------------------------------------------


class TestScoreMaintenance:
    """Tests for _score_maintenance."""

    def test_all_active(self):
        signals = [
            MaintainerSignal(name="pkg1", signal="active", days_since_release=5),
            MaintainerSignal(name="pkg2", signal="active", days_since_release=10),
        ]
        score = _score_maintenance(signals)
        assert score.score == 100.0
        assert score.grade == Grade.A

    def test_inactive(self):
        signals = [
            MaintainerSignal(name="dead-pkg", signal="inactive", days_since_release=500, note="No release in 500 days"),
        ]
        score = _score_maintenance(signals)
        assert score.score == 20.0
        assert score.grade == Grade.F

    def test_slow(self):
        signals = [
            MaintainerSignal(name="slow-pkg", signal="slow", days_since_release=200, note="Last release 200 days ago"),
        ]
        score = _score_maintenance(signals)
        assert score.score == 60.0
        assert score.grade == Grade.C

    def test_mixed_signals(self):
        signals = [
            MaintainerSignal(name="active", signal="active", days_since_release=10),
            MaintainerSignal(name="inactive", signal="inactive", days_since_release=500),
        ]
        score = _score_maintenance(signals)
        assert score.score == 60.0  # (100 + 20) / 2

    def test_empty_signals(self):
        score = _score_maintenance([])
        assert score.score == 50.0
        assert score.grade == Grade.C


# ---------------------------------------------------------------------------
# Transitive depth scoring tests
# ---------------------------------------------------------------------------


class TestScoreTransitiveDepth:
    """Tests for _score_transitive_depth."""

    def test_shallow_deps(self):
        depths = [
            TransitiveDepth(name="pkg1", max_depth=1, transitive_count=0),
            TransitiveDepth(name="pkg2", max_depth=0, transitive_count=0),
        ]
        score = _score_transitive_depth(depths)
        assert score.score == 100.0

    def test_deep_deps(self):
        depths = [
            TransitiveDepth(name="deep-pkg", max_depth=6, transitive_count=15),
        ]
        score = _score_transitive_depth(depths)
        assert score.score < 50.0

    def test_moderate_depth(self):
        depths = [
            TransitiveDepth(name="mod-pkg", max_depth=3, transitive_count=5),
        ]
        score = _score_transitive_depth(depths)
        assert score.score == 70.0

    def test_empty(self):
        score = _score_transitive_depth([])
        assert score.score == 100.0


# ---------------------------------------------------------------------------
# Outdated scoring tests
# ---------------------------------------------------------------------------


class TestScoreOutdated:
    """Tests for _score_outdated."""

    def test_all_current(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(name="pkg1", installed_version="1.0.0", latest_version="1.0.0"),
        ])
        score = _score_outdated(result)
        assert score.score == 100.0

    def test_major_behind(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(name="pkg1", installed_version="1.0.0", latest_version="2.0.0"),
        ])
        score = _score_outdated(result)
        assert score.score == 80.0  # 100 - 20
        assert "major" in score.recommendations[0].lower()

    def test_minor_behind(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(name="pkg1", installed_version="1.0.0", latest_version="1.1.0"),
        ])
        score = _score_outdated(result)
        assert score.score == 92.0  # 100 - 8

    def test_empty(self):
        result = ScanResult(project_path=".", packages=[])
        score = _score_outdated(result)
        assert score.score == 100.0


# ---------------------------------------------------------------------------
# Freshness analysis tests
# ---------------------------------------------------------------------------


class TestAnalyzeFreshness:
    """Tests for analyze_freshness."""

    def test_current_package(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(name="current-pkg", installed_version="1.0.0", latest_version="1.0.0",
                          status=HealthStatus.HEALTHY),
        ])
        freshness = analyze_freshness(result)
        assert len(freshness) == 1
        assert freshness[0].name == "current-pkg"
        assert freshness[0].freshness_ratio == 1.0
        assert freshness[0].days_behind == 0

    def test_outdated_with_date(self):
        from datetime import datetime, timedelta, timezone
        recent = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        result = ScanResult(project_path=".", packages=[
            PackageReport(
                name="old-pkg",
                installed_version="1.0.0",
                latest_version="2.0.0",
                status=HealthStatus.OUTDATED,
                last_release_date=recent,
            ),
        ])
        freshness = analyze_freshness(result)
        assert len(freshness) == 1
        assert freshness[0].days_behind is not None
        assert freshness[0].days_behind >= 29
        assert freshness[0].freshness_ratio is not None
        assert freshness[0].freshness_ratio < 1.0


# ---------------------------------------------------------------------------
# Maintainer signal tests
# ---------------------------------------------------------------------------


class TestAnalyzeMaintainerSignals:
    """Tests for analyze_maintainer_signals."""

    def test_unmaintained_package(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(name="dead-pkg", installed_version="1.0.0", status=HealthStatus.UNMAINTAINED),
        ])
        signals = analyze_maintainer_signals(result)
        assert len(signals) == 1
        assert signals[0].signal == "inactive"

    def test_yanked_package(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(name="yanked-pkg", installed_version="1.0.0", status=HealthStatus.YANKED),
        ])
        signals = analyze_maintainer_signals(result)
        assert signals[0].signal == "inactive"
        assert "yanked" in signals[0].note.lower()

    def test_removed_package(self):
        result = ScanResult(project_path=".", packages=[
            PackageReport(name="gone-pkg", installed_version="1.0.0", status=HealthStatus.REMOVED),
        ])
        signals = analyze_maintainer_signals(result)
        assert signals[0].signal == "inactive"
        assert "removed" in signals[0].note.lower()


# ---------------------------------------------------------------------------
# HealthReport tests
# ---------------------------------------------------------------------------


class TestHealthReport:
    """Tests for HealthReport model and to_dict."""

    def test_to_dict(self):
        report = HealthReport(
            project_path="/tmp/test",
            overall_score=85.0,
            overall_grade=Grade.B,
            categories=[
                CategoryScore(name="vulnerability", score=100.0, grade=Grade.A, weight=0.3),
            ],
            duration_seconds=1.5,
        )
        d = report.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert d["overall_score"] == 85.0
        assert d["overall_grade"] == "B"
        assert len(d["categories"]) == 1
        assert d["duration_seconds"] == 1.5

    def test_empty_report(self):
        report = HealthReport(project_path="/tmp/empty")
        d = report.to_dict()
        assert d["overall_score"] == 0.0
        assert d["categories"] == []


# ---------------------------------------------------------------------------
# CategoryScore tests
# ---------------------------------------------------------------------------


class TestCategoryScore:
    """Tests for CategoryScore model."""

    def test_to_dict(self):
        cs = CategoryScore(
            name="test",
            score=75.0,
            grade=Grade.B,
            weight=0.25,
            details={"count": 5},
            recommendations=["Fix issue A"],
        )
        d = cs.to_dict()
        assert d["name"] == "test"
        assert d["score"] == 75.0
        assert d["grade"] == "B"
        assert d["weight"] == 0.25
        assert d["details"]["count"] == 5
        assert d["recommendations"] == ["Fix issue A"]


# ---------------------------------------------------------------------------
# DependencyFreshness tests
# ---------------------------------------------------------------------------


class TestDependencyFreshness:
    """Tests for DependencyFreshness model."""

    def test_to_dict(self):
        f = DependencyFreshness(
            name="pkg",
            installed_version="1.0.0",
            latest_version="2.0.0",
            days_behind=90,
            freshness_ratio=0.753,
        )
        d = f.to_dict()
        assert d["name"] == "pkg"
        assert d["freshness_ratio"] == 0.753

    def test_to_dict_none_ratio(self):
        f = DependencyFreshness(
            name="pkg",
            installed_version="1.0.0",
            latest_version=None,
            days_behind=None,
            freshness_ratio=None,
        )
        d = f.to_dict()
        assert d["freshness_ratio"] is None


# ---------------------------------------------------------------------------
# Rendering tests (just ensure they don't crash)
# ---------------------------------------------------------------------------


class TestRendering:
    """Tests for render functions (smoke tests)."""

    def test_render_check_table(self):
        report = HealthReport(
            project_path="/tmp/test",
            overall_score=85.0,
            overall_grade=Grade.B,
            categories=[
                CategoryScore(name="vulnerability", score=100.0, grade=Grade.A, weight=0.3,
                              recommendations=["No issues"]),
                CategoryScore(name="freshness", score=80.0, grade=Grade.B, weight=0.2,
                              recommendations=["2 packages stale"]),
            ],
        )
        # Should not raise
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_check_table(report, console=console)
        output = buf.getvalue()
        assert "Overall Health" in output
        assert "B" in output

    def test_render_check_json(self):
        report = HealthReport(
            project_path="/tmp/test",
            overall_score=90.0,
            overall_grade=Grade.A,
        )
        from io import StringIO
        from rich.console import Console
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_check_json(report, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert data["overall_score"] == 90.0


# ---------------------------------------------------------------------------
# Integration test with mock
# ---------------------------------------------------------------------------


class TestRunCheck:
    """Tests for the run_check orchestrator."""

    @patch("depcheck.check.scan_project")
    @patch("depcheck.check.run_audit")
    def test_run_check_basic(self, mock_audit, mock_scan):
        mock_scan.return_value = ScanResult(project_path=".", packages=[
            PackageReport(name="test-pkg", installed_version="1.0.0", latest_version="1.0.0",
                          status=HealthStatus.HEALTHY),
        ])
        mock_result = MagicMock()
        mock_result.risk_level = MagicMock(value="none")
        mock_audit.return_value = mock_result

        report = run_check(project_path="/tmp/test-project")
        assert report.overall_score > 0
        assert len(report.categories) == 6

    @patch("depcheck.check.scan_project")
    @patch("depcheck.check.run_audit")
    def test_run_check_with_vulns(self, mock_audit, mock_scan):
        vuln = Vulnerability(vuln_id="CVE-1", summary="Bad", severity="high", url="https://x.com")
        mock_scan.return_value = ScanResult(project_path=".", packages=[
            PackageReport(name="vuln-pkg", installed_version="1.0.0", latest_version="2.0.0",
                          status=HealthStatus.VULNERABLE, vulnerabilities=[vuln]),
        ])
        mock_result = MagicMock()
        mock_result.risk_level = MagicMock(value="high")
        mock_audit.return_value = mock_result

        report = run_check(project_path="/tmp/test-project")
        assert report.overall_score < 100.0
        # Vulnerability category should be penalized
        vuln_cat = next(c for c in report.categories if c.name == "vulnerability")
        assert vuln_cat.score < 100.0
