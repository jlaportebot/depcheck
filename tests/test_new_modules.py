"""Comprehensive tests for depcheck: budget, risks, advisories, graph, policy modules."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# ─── Budget Module Tests ───────────────────────────────────────────────────


class TestRiskDimension:
    """Tests for RiskDimension enum."""

    def test_all_dimensions(self):
        from depcheck.risks import RiskDimension

        dims = list(RiskDimension)
        assert len(dims) == 5
        assert RiskDimension.VULNERABILITY in dims
        assert RiskDimension.MAINTENANCE in dims
        assert RiskDimension.AGE in dims
        assert RiskDimension.POPULARITY in dims
        assert RiskDimension.LICENSE in dims


class TestRiskSeverity:
    """Tests for RiskSeverity enum."""

    def test_severity_levels(self):
        from depcheck.risks import RiskSeverity

        assert RiskSeverity.CRITICAL.value == "critical"
        assert RiskSeverity.HIGH.value == "high"
        assert RiskSeverity.MEDIUM.value == "medium"
        assert RiskSeverity.LOW.value == "low"
        assert RiskSeverity.MINIMAL.value == "minimal"


class TestDimensionScore:
    """Tests for DimensionScore data model."""

    def test_weighted_score(self):
        from depcheck.risks import DimensionScore, RiskDimension

        ds = DimensionScore(
            dimension=RiskDimension.VULNERABILITY,
            score=0.8,
            weight=0.35,
        )
        assert ds.weighted_score == pytest.approx(0.28)

    def test_to_dict(self):
        from depcheck.risks import DimensionScore, RiskDimension

        ds = DimensionScore(
            dimension=RiskDimension.MAINTENANCE,
            score=0.5,
            weight=0.25,
            details="Unmaintained",
            contributing_factors=["No release in 400 days"],
        )
        d = ds.to_dict()
        assert d["dimension"] == "maintenance"
        assert d["score"] == 0.5
        assert d["details"] == "Unmaintained"


class TestRiskEntry:
    """Tests for RiskEntry data model."""

    def test_basic_entry(self):
        from depcheck.risks import RiskEntry, RiskSeverity

        entry = RiskEntry(
            package="test-pkg",
            version="1.0.0",
            composite_score=0.5,
            severity=RiskSeverity.MEDIUM,
        )
        assert entry.package == "test-pkg"
        assert entry.severity_rank == 2

    def test_severity_rank(self):
        from depcheck.risks import RiskEntry, RiskSeverity

        critical = RiskEntry(package="x", version="1.0", composite_score=0.9, severity=RiskSeverity.CRITICAL)  # noqa: E501
        minimal = RiskEntry(package="y", version="1.0", composite_score=0.1, severity=RiskSeverity.MINIMAL)  # noqa: E501
        assert critical.severity_rank > minimal.severity_rank

    def test_to_dict(self):
        from depcheck.risks import RiskEntry, RiskSeverity

        entry = RiskEntry(
            package="test-pkg",
            version="1.0.0",
            composite_score=0.5,
            severity=RiskSeverity.MEDIUM,
        )
        d = entry.to_dict()
        assert d["package"] == "test-pkg"
        assert d["severity"] == "medium"
        assert d["composite_score"] == 0.5


class TestRiskReport:
    """Tests for RiskReport data model."""

    def test_empty_report(self):
        from depcheck.risks import RiskReport

        report = RiskReport(project_path="/test")
        assert report.at_risk_packages == []
        assert report.priority_remediations == []

    def test_at_risk_packages(self):
        from depcheck.risks import RemediationAction, RiskEntry, RiskReport, RiskSeverity

        entries = [
            RiskEntry(package="safe", version="1.0", composite_score=0.1, severity=RiskSeverity.MINIMAL),  # noqa: E501
            RiskEntry(package="risky", version="1.0", composite_score=0.7, severity=RiskSeverity.HIGH,  # noqa: E501
                       remediation=RemediationAction.UPDATE),
        ]
        report = RiskReport(project_path="/test", entries=entries)
        assert len(report.at_risk_packages) == 1
        assert report.at_risk_packages[0].package == "risky"

    def test_priority_remediations(self):
        from depcheck.risks import RemediationAction, RiskEntry, RiskReport, RiskSeverity

        entries = [
            RiskEntry(package="ok", version="1.0", composite_score=0.1, severity=RiskSeverity.MINIMAL,  # noqa: E501
                       remediation=RemediationAction.NONE),
            RiskEntry(package="needs-update", version="1.0", composite_score=0.7, severity=RiskSeverity.HIGH,  # noqa: E501
                       remediation=RemediationAction.UPDATE),
            RiskEntry(package="needs-replace", version="1.0", composite_score=0.9, severity=RiskSeverity.CRITICAL,  # noqa: E501
                       remediation=RemediationAction.REPLACE),
        ]
        report = RiskReport(project_path="/test", entries=entries)
        prios = report.priority_remediations
        assert len(prios) == 2
        assert prios[0].package == "needs-replace"

    def test_to_dict(self):
        from depcheck.risks import RiskReport

        report = RiskReport(project_path="/test", total_packages=5, avg_score=0.3)
        d = report.to_dict()
        assert d["project_path"] == "/test"
        assert d["total_packages"] == 5


class TestClassifySeverity:
    """Tests for _classify_severity function."""

    def test_critical_threshold(self):
        from depcheck.risks import RiskSeverity, _classify_severity

        assert _classify_severity(0.85) == RiskSeverity.CRITICAL
        assert _classify_severity(0.80) == RiskSeverity.CRITICAL

    def test_high_threshold(self):
        from depcheck.risks import RiskSeverity, _classify_severity

        assert _classify_severity(0.65) == RiskSeverity.HIGH
        assert _classify_severity(0.60) == RiskSeverity.HIGH

    def test_medium_threshold(self):
        from depcheck.risks import RiskSeverity, _classify_severity

        assert _classify_severity(0.45) == RiskSeverity.MEDIUM
        assert _classify_severity(0.40) == RiskSeverity.MEDIUM

    def test_low_threshold(self):
        from depcheck.risks import RiskSeverity, _classify_severity

        assert _classify_severity(0.25) == RiskSeverity.LOW
        assert _classify_severity(0.20) == RiskSeverity.LOW

    def test_minimal_threshold(self):
        from depcheck.risks import RiskSeverity, _classify_severity

        assert _classify_severity(0.1) == RiskSeverity.MINIMAL
        assert _classify_severity(0.0) == RiskSeverity.MINIMAL


class TestScoreVulnerability:
    """Tests for _score_vulnerability function."""

    def test_no_vulnerabilities(self):
        from depcheck.models import PackageReport
        from depcheck.risks import RiskDimension, _score_vulnerability

        pkg = PackageReport(name="safe-pkg", installed_version="1.0.0")
        ds = _score_vulnerability(pkg)
        assert ds.dimension == RiskDimension.VULNERABILITY
        assert ds.score == 0.0

    def test_with_critical_vuln(self):
        from depcheck.models import PackageReport, Vulnerability
        from depcheck.risks import RiskDimension, _score_vulnerability

        pkg = PackageReport(
            name="vuln-pkg",
            installed_version="1.0.0",
            vulnerabilities=[
                Vulnerability(vuln_id="CVE-2023-001", summary="RCE", severity="CRITICAL", url="https://example.com"),
            ],
        )
        ds = _score_vulnerability(pkg)
        assert ds.score > 0
        assert ds.dimension == RiskDimension.VULNERABILITY


class TestScoreMaintenance:
    """Tests for _score_maintenance function."""

    def test_healthy_package(self):
        from depcheck.models import HealthStatus, PackageReport
        from depcheck.risks import _score_maintenance

        pkg = PackageReport(
            name="healthy-pkg",
            installed_version="1.0.0",
            status=HealthStatus.HEALTHY,
            last_release_date="2025-05-01",
        )
        ds = _score_maintenance(pkg)
        assert ds.score < 0.6  # Health status adds to age component

    def test_unmaintained_package(self):
        from depcheck.models import HealthStatus, PackageReport
        from depcheck.risks import _score_maintenance

        pkg = PackageReport(
            name="dead-pkg",
            installed_version="1.0.0",
            status=HealthStatus.UNMAINTAINED,
        )
        ds = _score_maintenance(pkg)
        assert ds.score >= 0.5


class TestScoreLicense:
    """Tests for _score_license function."""

    def test_no_license_info(self):
        from depcheck.models import PackageReport
        from depcheck.risks import _score_license

        pkg = PackageReport(name="no-lic", installed_version="1.0.0")
        ds = _score_license(pkg)
        assert ds.score == 0.5

    def test_permissive_license(self):
        from depcheck.models import LicenseInfo, PackageReport
        from depcheck.risks import _score_license

        pkg = PackageReport(
            name="mit-pkg",
            installed_version="1.0.0",
            license_info=LicenseInfo(spdx_id="MIT", category="permissive"),
        )
        ds = _score_license(pkg)
        assert ds.score == 0.0

    def test_copyleft_license(self):
        from depcheck.models import LicenseInfo, PackageReport
        from depcheck.risks import _score_license

        pkg = PackageReport(
            name="gpl-pkg",
            installed_version="1.0.0",
            license_info=LicenseInfo(spdx_id="GPL-3.0", category="copyleft"),
        )
        ds = _score_license(pkg)
        assert ds.score == 0.8


class TestAssessPackageRisk:
    """Tests for assess_package_risk function."""

    def test_healthy_package(self):
        from depcheck.models import HealthStatus, PackageReport
        from depcheck.risks import RiskSeverity, assess_package_risk

        pkg = PackageReport(
            name="healthy-pkg",
            installed_version="1.0.0",
            status=HealthStatus.HEALTHY,
        )
        entry = assess_package_risk(pkg)
        assert entry.package == "healthy-pkg"
        assert entry.composite_score < 0.4
        assert entry.severity in (RiskSeverity.MINIMAL, RiskSeverity.LOW)

    def test_vulnerable_package(self):
        from depcheck.models import HealthStatus, PackageReport, Vulnerability
        from depcheck.risks import RiskSeverity, assess_package_risk

        pkg = PackageReport(
            name="vuln-pkg",
            installed_version="1.0.0",
            status=HealthStatus.VULNERABLE,
            vulnerabilities=[
                Vulnerability(vuln_id="CVE-2023-001", summary="RCE", severity="CRITICAL", url=""),
            ],
        )
        entry = assess_package_risk(pkg)
        assert entry.composite_score > 0.4
        assert entry.severity in (RiskSeverity.HIGH, RiskSeverity.CRITICAL, RiskSeverity.MEDIUM)

    def test_all_dimensions_scored(self):
        from depcheck.models import HealthStatus, PackageReport
        from depcheck.risks import RiskDimension, assess_package_risk

        pkg = PackageReport(name="pkg", installed_version="1.0.0", status=HealthStatus.HEALTHY)
        entry = assess_package_risk(pkg)
        dim_names = {ds.dimension for ds in entry.dimension_scores}
        assert dim_names == {
            RiskDimension.VULNERABILITY,
            RiskDimension.MAINTENANCE,
            RiskDimension.AGE,
            RiskDimension.POPULARITY,
            RiskDimension.LICENSE,
        }


class TestAssessRisks:
    """Tests for the assess_risks function."""

    def test_nonexistent_path(self):
        from depcheck.risks import assess_risks

        report = assess_risks(project_path="/nonexistent/path")
        assert report.errors

    def test_with_mock_scan(self):
        from depcheck.models import HealthStatus, PackageReport, ScanResult
        from depcheck.risks import assess_risks

        mock_packages = [
            PackageReport(name="pkg-a", installed_version="1.0.0", status=HealthStatus.HEALTHY),
            PackageReport(name="pkg-b", installed_version="2.0.0", status=HealthStatus.OUTDATED),
        ]

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("depcheck.risks.scan_project") as mock_scan:
            mock_scan.return_value = ScanResult(
                project_path=tmpdir,
                packages=mock_packages,
                errors=[],
            )
            report = assess_risks(project_path=tmpdir)
            assert report.total_packages == 2
            assert len(report.entries) == 2

    def test_custom_weights(self):
        from depcheck.models import HealthStatus, PackageReport, ScanResult
        from depcheck.risks import RiskDimension, assess_risks

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("depcheck.risks.scan_project") as mock_scan:
            mock_scan.return_value = ScanResult(
                project_path=tmpdir,
                packages=[PackageReport(name="p", installed_version="1.0", status=HealthStatus.HEALTHY)],  # noqa: E501
                errors=[],
            )
            custom_weights = {
                RiskDimension.VULNERABILITY: 0.5,
                RiskDimension.MAINTENANCE: 0.2,
                RiskDimension.AGE: 0.1,
                RiskDimension.POPULARITY: 0.1,
                RiskDimension.LICENSE: 0.1,
            }
            report = assess_risks(project_path=tmpdir, weights=custom_weights)
            assert report.total_packages == 1


# ─── Advisories Module Tests ──────────────────────────────────────────────


class TestAdvisorySource:
    """Tests for AdvisorySource enum."""

    def test_sources(self):
        from depcheck.advisories import AdvisorySource

        assert AdvisorySource.OSV.value == "osv"
        assert AdvisorySource.PYPA.value == "pypa"
        assert AdvisorySource.GITHUB.value == "github"
        assert AdvisorySource.MANUAL.value == "manual"


class TestAdvisoryStatus:
    """Tests for AdvisoryStatus enum."""

    def test_statuses(self):
        from depcheck.advisories import AdvisoryStatus

        assert AdvisoryStatus.ACTIVE.value == "active"
        assert AdvisoryStatus.PATCHED.value == "patched"
        assert AdvisoryStatus.WITHDRAWN.value == "withdrawn"
        assert AdvisoryStatus.DISPUTED.value == "disputed"


class TestAffectedRange:
    """Tests for AffectedRange data model."""

    def test_basic_range(self):
        from depcheck.advisories import AffectedRange

        rng = AffectedRange(introduced="1.0.0", fixed="2.0.0")
        assert rng.introduced == "1.0.0"
        assert rng.fixed == "2.0.0"

    def test_unfixed_range(self):
        from depcheck.advisories import AffectedRange

        rng = AffectedRange(introduced="1.0.0")
        assert rng.fixed is None

    def test_to_dict(self):
        from depcheck.advisories import AffectedRange

        rng = AffectedRange(introduced="1.0.0", fixed="2.0.0", last_affected="1.9.9")
        d = rng.to_dict()
        assert d["introduced"] == "1.0.0"
        assert d["fixed"] == "2.0.0"
        assert d["last_affected"] == "1.9.9"


class TestAdvisoryEntry:
    """Tests for AdvisoryEntry data model."""

    def test_basic_entry(self):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource

        entry = AdvisoryEntry(
            advisory_id="CVE-2023-001",
            source=AdvisorySource.OSV,
            package="test-pkg",
            summary="Test vulnerability",
            severity="HIGH",
            url="https://osv.dev/CVE-2023-001",
        )
        assert entry.advisory_id == "CVE-2023-001"
        assert entry.severity_rank == 3

    def test_severity_rank(self):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource

        critical = AdvisoryEntry(
            advisory_id="C-1", source=AdvisorySource.OSV, package="x",
            summary="", severity="CRITICAL", url="",
        )
        low = AdvisoryEntry(
            advisory_id="L-1", source=AdvisorySource.OSV, package="x",
            summary="", severity="LOW", url="",
        )
        assert critical.severity_rank > low.severity_rank

    def test_is_patchable(self):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource, AffectedRange

        entry = AdvisoryEntry(
            advisory_id="P-1", source=AdvisorySource.OSV, package="x",
            summary="", severity="HIGH", url="",
            affected_ranges=[AffectedRange(introduced="1.0.0", fixed="2.0.0")],
        )
        assert entry.is_patchable

    def test_not_patchable(self):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource, AffectedRange

        entry = AdvisoryEntry(
            advisory_id="U-1", source=AdvisorySource.OSV, package="x",
            summary="", severity="HIGH", url="",
            affected_ranges=[AffectedRange(introduced="1.0.0")],
        )
        assert not entry.is_patchable

    def test_to_dict(self):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource

        entry = AdvisoryEntry(
            advisory_id="CVE-2023-001",
            source=AdvisorySource.OSV,
            package="test-pkg",
            summary="Test vulnerability",
            severity="HIGH",
            url="https://osv.dev/CVE-2023-001",
            aliases=["CVE-2023-001"],
        )
        d = entry.to_dict()
        assert d["advisory_id"] == "CVE-2023-001"
        assert d["source"] == "osv"
        assert d["is_patchable"] is False


class TestPackageAdvisorySummary:
    """Tests for PackageAdvisorySummary data model."""

    def test_basic_summary(self):
        from depcheck.advisories import PackageAdvisorySummary

        summary = PackageAdvisorySummary(
            package="test-pkg",
            version="1.0.0",
            total_advisories=3,
            critical_count=1,
            high_count=2,
        )
        assert summary.has_critical
        assert not summary.has_unpatched

    def test_has_unpatched(self):
        from depcheck.advisories import PackageAdvisorySummary

        summary = PackageAdvisorySummary(
            package="test-pkg",
            version="1.0.0",
            unpatchable_count=2,
        )
        assert summary.has_unpatched

    def test_to_dict(self):
        from depcheck.advisories import PackageAdvisorySummary

        summary = PackageAdvisorySummary(
            package="test-pkg", version="1.0.0", total_advisories=2,
        )
        d = summary.to_dict()
        assert d["package"] == "test-pkg"
        assert d["total_advisories"] == 2


class TestAdvisoryReport:
    """Tests for AdvisoryReport data model."""

    def test_affected_packages(self):
        from depcheck.advisories import AdvisoryReport, PackageAdvisorySummary

        pkgs = [
            PackageAdvisorySummary(package="safe", version="1.0", total_advisories=0),
            PackageAdvisorySummary(package="vuln", version="1.0", total_advisories=2),
        ]
        report = AdvisoryReport(project_path="/test", packages=pkgs)
        assert len(report.affected_packages) == 1
        assert len(report.clean_packages) == 1

    def test_to_dict(self):
        from depcheck.advisories import AdvisoryReport

        report = AdvisoryReport(project_path="/test", total_advisories=5)
        d = report.to_dict()
        assert d["project_path"] == "/test"
        assert d["total_advisories"] == 5


class TestLookupAdvisories:
    """Tests for lookup_advisories function."""

    @patch("depcheck.advisories._fetch_osv_advisories", return_value=[])
    @patch("depcheck.advisories._fetch_github_advisories", return_value=[])
    @patch("depcheck.advisories._fetch_pypa_advisory", return_value=[])
    def test_no_advisories(self, mock_pypa, mock_gh, mock_osv):
        from depcheck.advisories import lookup_advisories

        results = lookup_advisories("nonexistent-pkg-xyz", version="1.0.0")
        assert isinstance(results, list)

    @patch("depcheck.advisories._fetch_github_advisories", return_value=[])
    @patch("depcheck.advisories._fetch_pypa_advisory", return_value=[])
    @patch("depcheck.advisories._fetch_osv_advisories")
    def test_deduplication(self, mock_osv, mock_pypa, mock_gh):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource, lookup_advisories

        entry = AdvisoryEntry(
            advisory_id="GHSA-abc-123",
            source=AdvisorySource.GITHUB,
            package="test",
            summary="Test",
            severity="HIGH",
            url="https://example.com",
        )
        mock_osv.return_value = [entry]
        results = lookup_advisories("test", version="1.0.0", sources=[AdvisorySource.OSV])
        assert len(results) == 1

    @patch("depcheck.advisories._fetch_github_advisories", return_value=[])
    @patch("depcheck.advisories._fetch_pypa_advisory", return_value=[])
    @patch("depcheck.advisories._fetch_osv_advisories")
    def test_sorted_by_severity(self, mock_osv, mock_pypa, mock_gh):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource, lookup_advisories

        entries = [
            AdvisoryEntry(advisory_id="L-1", source=AdvisorySource.OSV, package="x",
                          summary="Low", severity="LOW", url=""),
            AdvisoryEntry(advisory_id="C-1", source=AdvisorySource.OSV, package="x",
                          summary="Critical", severity="CRITICAL", url=""),
            AdvisoryEntry(advisory_id="M-1", source=AdvisorySource.OSV, package="x",
                          summary="Medium", severity="MEDIUM", url=""),
        ]
        mock_osv.return_value = entries
        results = lookup_advisories("test", version="1.0.0", sources=[AdvisorySource.OSV])
        assert results[0].severity == "CRITICAL"
        assert results[-1].severity == "LOW"


class TestSearchAdvisories:
    """Tests for search_advisories function."""

    @patch("depcheck.advisories.lookup_advisories")
    def test_severity_filter(self, mock_lookup):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource, search_advisories

        mock_lookup.return_value = [
            AdvisoryEntry(advisory_id="C-1", source=AdvisorySource.OSV, package="x",
                          summary="", severity="CRITICAL", url=""),
            AdvisoryEntry(advisory_id="L-1", source=AdvisorySource.OSV, package="x",
                          summary="", severity="LOW", url=""),
        ]
        results = search_advisories("test", severity="CRITICAL")
        assert all(r.severity == "CRITICAL" for r in results)

    @patch("depcheck.advisories.lookup_advisories")
    def test_patched_only_filter(self, mock_lookup):
        from depcheck.advisories import (
            AdvisoryEntry,
            AdvisorySource,
            AffectedRange,
            search_advisories,
        )

        mock_lookup.return_value = [
            AdvisoryEntry(advisory_id="P-1", source=AdvisorySource.OSV, package="x",
                          summary="", severity="HIGH", url="",
                          affected_ranges=[AffectedRange(introduced="1.0", fixed="2.0")]),
            AdvisoryEntry(advisory_id="U-1", source=AdvisorySource.OSV, package="x",
                          summary="", severity="HIGH", url="",
                          affected_ranges=[AffectedRange(introduced="1.0")]),
        ]
        results = search_advisories("test", patched_only=True)
        assert len(results) == 1
        assert results[0].is_patchable

    @patch("depcheck.advisories.lookup_advisories")
    def test_source_filter(self, mock_lookup):
        from depcheck.advisories import AdvisoryEntry, AdvisorySource, search_advisories

        mock_lookup.return_value = [
            AdvisoryEntry(advisory_id="O-1", source=AdvisorySource.OSV, package="x",
                          summary="", severity="HIGH", url=""),
            AdvisoryEntry(advisory_id="G-1", source=AdvisorySource.GITHUB, package="x",
                          summary="", severity="HIGH", url=""),
        ]
        results = search_advisories("test", source=AdvisorySource.GITHUB)
        assert len(results) == 1
        assert results[0].source == AdvisorySource.GITHUB


# ─── Graph Module Tests ────────────────────────────────────────────────────


class TestRuleSeverity:
    """Tests for RuleSeverity enum."""

    def test_severity_values(self):
        from depcheck.policy import RuleSeverity

        assert RuleSeverity.ERROR.value == "error"
        assert RuleSeverity.WARNING.value == "warning"
        assert RuleSeverity.INFO.value == "info"


class TestRuleCategory:
    """Tests for RuleCategory enum."""

    def test_categories(self):
        from depcheck.policy import RuleCategory

        assert RuleCategory.LICENSE.value == "license"
        assert RuleCategory.VERSION.value == "version"
        assert RuleCategory.AGE.value == "age"
        assert RuleCategory.PINNING.value == "pinning"
        assert RuleCategory.DEPTH.value == "depth"
        assert RuleCategory.VULNERABILITY.value == "vulnerability"
        assert RuleCategory.MAINTENANCE.value == "maintenance"
        assert RuleCategory.SIZE.value == "size"
        assert RuleCategory.CUSTOM.value == "custom"


class TestPolicyRule:
    """Tests for PolicyRule data model."""

    def test_basic_rule(self):
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity

        rule = PolicyRule(
            name="no-gpl",
            category=RuleCategory.LICENSE,
            severity=RuleSeverity.ERROR,
            deny_copyleft=True,
        )
        assert rule.name == "no-gpl"
        assert rule.deny_copyleft is True

    def test_to_dict(self):
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity

        rule = PolicyRule(
            name="max-age",
            category=RuleCategory.AGE,
            severity=RuleSeverity.WARNING,
            max_age_days=365,
        )
        d = rule.to_dict()
        assert d["name"] == "max-age"
        assert d["category"] == "age"
        assert d["max_age_days"] == 365

    def test_version_constraints(self):
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity

        rule = PolicyRule(
            name="min-versions",
            category=RuleCategory.VERSION,
            severity=RuleSeverity.ERROR,
            require_version_min={"requests": "2.28.0"},
            require_version_max={"numpy": "1.26.0"},
        )
        assert rule.require_version_min == {"requests": "2.28.0"}
        assert rule.require_version_max == {"numpy": "1.26.0"}


class TestViolation:
    """Tests for Violation data model."""

    def test_basic_violation(self):
        from depcheck.policy import RuleCategory, RuleSeverity, Violation

        viol = Violation(
            rule_name="no-gpl",
            package="gpl-pkg",
            version="1.0.0",
            severity=RuleSeverity.ERROR,
            category=RuleCategory.LICENSE,
            message="Copyleft license detected",
        )
        assert viol.rule_name == "no-gpl"

    def test_to_dict(self):
        from depcheck.policy import RuleCategory, RuleSeverity, Violation

        viol = Violation(
            rule_name="test",
            package="pkg",
            version="1.0",
            severity=RuleSeverity.WARNING,
            category=RuleCategory.AGE,
            message="Too old",
        )
        d = viol.to_dict()
        assert d["severity"] == "warning"
        assert d["category"] == "age"


class TestPolicyReport:
    """Tests for PolicyReport data model."""

    def test_compliant(self):
        from depcheck.policy import PolicyReport

        report = PolicyReport(project_path="/test", error_count=0, total_packages=5)
        assert report.is_compliant
        assert report.compliance_score == 100.0

    def test_non_compliant(self):
        from depcheck.policy import PolicyReport, RuleCategory, RuleSeverity, Violation

        report = PolicyReport(
            project_path="/test",
            error_count=1,
            total_packages=5,
            violations=[
                Violation("test", "pkg", "1.0", RuleSeverity.ERROR, RuleCategory.LICENSE, "err"),
            ],
        )
        assert not report.is_compliant
        assert report.compliance_score < 100.0

    def test_compliance_score_calculation(self):
        from depcheck.policy import PolicyReport, RuleCategory, RuleSeverity, Violation

        report = PolicyReport(
            project_path="/test",
            total_packages=10,
            violations=[
                Violation("r1", "p1", "1.0", RuleSeverity.ERROR, RuleCategory.LICENSE, "err"),
                Violation("r2", "p2", "1.0", RuleSeverity.ERROR, RuleCategory.LICENSE, "err"),
            ],
            error_count=2,
        )
        assert report.compliance_score == 80.0

    def test_zero_packages(self):
        from depcheck.policy import PolicyReport

        report = PolicyReport(project_path="/test", total_packages=0)
        assert report.compliance_score == 100.0

    def test_to_dict(self):
        from depcheck.policy import PolicyReport

        report = PolicyReport(project_path="/test", error_count=0, total_packages=3)
        d = report.to_dict()
        assert d["is_compliant"] is True
        assert d["compliance_score"] == 100.0


class TestPolicyConfig:
    """Tests for PolicyConfig data model."""

    def test_from_dict_license(self):
        from depcheck.policy import PolicyConfig, RuleCategory

        data = {"license": {"deny": ["GPL-3.0"], "deny_copyleft": True}}
        config = PolicyConfig.from_dict(data)
        assert len(config.rules) == 1
        assert config.rules[0].category == RuleCategory.LICENSE
        assert config.rules[0].deny_copyleft is True

    def test_from_dict_version(self):
        from depcheck.policy import PolicyConfig, RuleCategory

        data = {"version": {"max_age_days": 365, "require_pinned": True}}
        config = PolicyConfig.from_dict(data)
        assert len(config.rules) == 2
        categories = {r.category for r in config.rules}
        assert RuleCategory.AGE in categories
        assert RuleCategory.PINNING in categories

    def test_from_dict_vulnerability(self):
        from depcheck.policy import PolicyConfig

        data = {"vulnerability": {"max_severity": "HIGH"}}
        config = PolicyConfig.from_dict(data)
        assert len(config.rules) == 1
        assert config.rules[0].max_severity == "HIGH"

    def test_from_dict_packages_deny(self):
        from depcheck.policy import PolicyConfig

        data = {"packages": {"deny": ["pkg-a", "pkg-b"]}}
        config = PolicyConfig.from_dict(data)
        assert len(config.rules) == 1
        assert config.rules[0].deny_packages == ["pkg-a", "pkg-b"]

    def test_from_dict_packages_allow(self):
        from depcheck.policy import PolicyConfig

        data = {"packages": {"allow": ["pkg-a"]}}
        config = PolicyConfig.from_dict(data)
        assert len(config.rules) == 1
        assert config.rules[0].allow_packages == ["pkg-a"]

    def test_from_dict_maintenance(self):
        from depcheck.policy import PolicyConfig

        data = {"maintenance": {"min_maintained_days": 180}}
        config = PolicyConfig.from_dict(data)
        assert len(config.rules) == 1
        assert config.rules[0].min_maintained_days == 180

    def test_from_dict_depth(self):
        from depcheck.policy import PolicyConfig

        data = {"depth": {"max_depth": 3}}
        config = PolicyConfig.from_dict(data)
        assert len(config.rules) == 1
        assert config.rules[0].max_depth == 3

    def test_from_pyproject_no_policy(self):
        from depcheck.policy import PolicyConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            result = PolicyConfig.from_pyproject(Path(tmpdir))
            assert result is None

    def test_from_pyproject_with_policy(self):
        from depcheck.policy import PolicyConfig

        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject = Path(tmpdir) / "pyproject.toml"
            pyproject.write_text(
                '[tool.depcheck.policy.license]\ndeny_copyleft = true\n'
            )
            result = PolicyConfig.from_pyproject(Path(tmpdir))
            assert result is not None
            assert len(result.rules) == 1

    def test_empty_config(self):
        from depcheck.policy import PolicyConfig

        config = PolicyConfig.from_dict({})
        assert len(config.rules) == 0


class TestEvaluateLicenseRule:
    """Tests for _evaluate_license_rule function."""

    def test_permissive_passes(self):
        from depcheck.models import LicenseInfo, PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_license_rule

        rule = PolicyRule(
            name="no-gpl", category=RuleCategory.LICENSE,
            severity=RuleSeverity.ERROR, deny_copyleft=True,
        )
        pkg = PackageReport(
            name="mit-pkg", installed_version="1.0.0",
            license_info=LicenseInfo(spdx_id="MIT", category="permissive"),
        )
        result = _evaluate_license_rule(rule, pkg)
        assert result is None

    def test_copyleft_fails(self):
        from depcheck.models import LicenseInfo, PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_license_rule

        rule = PolicyRule(
            name="no-gpl", category=RuleCategory.LICENSE,
            severity=RuleSeverity.ERROR, deny_copyleft=True,
        )
        pkg = PackageReport(
            name="gpl-pkg", installed_version="1.0.0",
            license_info=LicenseInfo(spdx_id="GPL-3.0", category="copyleft"),
        )
        result = _evaluate_license_rule(rule, pkg)
        assert result is not None
        assert result.severity == RuleSeverity.ERROR

    def test_deny_list(self):
        from depcheck.models import LicenseInfo, PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_license_rule

        rule = PolicyRule(
            name="no-sspl", category=RuleCategory.LICENSE,
            severity=RuleSeverity.ERROR, deny_licenses=["SSPL-1.0"],
        )
        pkg = PackageReport(
            name="sspl-pkg", installed_version="1.0.0",
            license_info=LicenseInfo(spdx_id="SSPL-1.0", category="proprietary"),
        )
        result = _evaluate_license_rule(rule, pkg)
        assert result is not None

    def test_allow_list_blocks_others(self):
        from depcheck.models import LicenseInfo, PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_license_rule

        rule = PolicyRule(
            name="only-mit", category=RuleCategory.LICENSE,
            severity=RuleSeverity.ERROR, allow_licenses=["MIT", "Apache-2.0"],
        )
        pkg = PackageReport(
            name="gpl-pkg", installed_version="1.0.0",
            license_info=LicenseInfo(spdx_id="GPL-3.0", category="copyleft"),
        )
        result = _evaluate_license_rule(rule, pkg)
        assert result is not None

    def test_allow_list_passes(self):
        from depcheck.models import LicenseInfo, PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_license_rule

        rule = PolicyRule(
            name="only-mit", category=RuleCategory.LICENSE,
            severity=RuleSeverity.ERROR, allow_licenses=["MIT", "Apache-2.0"],
        )
        pkg = PackageReport(
            name="mit-pkg", installed_version="1.0.0",
            license_info=LicenseInfo(spdx_id="MIT", category="permissive"),
        )
        result = _evaluate_license_rule(rule, pkg)
        assert result is None

    def test_unknown_with_strict(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_license_rule

        rule = PolicyRule(
            name="strict-lic", category=RuleCategory.LICENSE,
            severity=RuleSeverity.ERROR, strict_unknown=True,
        )
        pkg = PackageReport(name="unknown-pkg", installed_version="1.0.0")
        result = _evaluate_license_rule(rule, pkg)
        assert result is not None

    def test_unknown_without_strict(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_license_rule

        rule = PolicyRule(
            name="lax-lic", category=RuleCategory.LICENSE,
            severity=RuleSeverity.ERROR, strict_unknown=False,
        )
        pkg = PackageReport(name="unknown-pkg", installed_version="1.0.0")
        result = _evaluate_license_rule(rule, pkg)
        assert result is None


class TestEvaluateAgeRule:
    """Tests for _evaluate_age_rule function."""

    def test_recent_package_passes(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_age_rule

        rule = PolicyRule(
            name="max-age", category=RuleCategory.AGE,
            severity=RuleSeverity.WARNING, max_age_days=365,
        )
        pkg = PackageReport(
            name="recent-pkg", installed_version="1.0.0",
            last_release_date="2026-01-01",
        )
        result = _evaluate_age_rule(rule, pkg)
        assert result is None

    def test_old_package_fails(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_age_rule

        rule = PolicyRule(
            name="max-age", category=RuleCategory.AGE,
            severity=RuleSeverity.WARNING, max_age_days=365,
        )
        pkg = PackageReport(
            name="old-pkg", installed_version="1.0.0",
            last_release_date="2023-01-01",
        )
        result = _evaluate_age_rule(rule, pkg)
        assert result is not None

    def test_no_max_age(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_age_rule

        rule = PolicyRule(
            name="no-age-limit", category=RuleCategory.AGE,
            severity=RuleSeverity.WARNING,
        )
        pkg = PackageReport(name="pkg", installed_version="1.0.0")
        result = _evaluate_age_rule(rule, pkg)
        assert result is None

    def test_no_release_date(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_age_rule

        rule = PolicyRule(
            name="max-age", category=RuleCategory.AGE,
            severity=RuleSeverity.WARNING, max_age_days=365,
        )
        pkg = PackageReport(name="pkg", installed_version="1.0.0")
        result = _evaluate_age_rule(rule, pkg)
        assert result is None  # Can't evaluate without date


class TestEvaluateVulnerabilityRule:
    """Tests for _evaluate_vulnerability_rule function."""

    def test_no_vulns_passes(self):
        from depcheck.models import PackageReport
        from depcheck.policy import (
            PolicyRule,
            RuleCategory,
            RuleSeverity,
            _evaluate_vulnerability_rule,
        )

        rule = PolicyRule(
            name="no-high", category=RuleCategory.VULNERABILITY,
            severity=RuleSeverity.ERROR, max_severity="HIGH",
        )
        pkg = PackageReport(name="safe-pkg", installed_version="1.0.0")
        result = _evaluate_vulnerability_rule(rule, pkg)
        assert result is None

    def test_critical_vuln_fails(self):
        from depcheck.models import PackageReport, Vulnerability
        from depcheck.policy import (
            PolicyRule,
            RuleCategory,
            RuleSeverity,
            _evaluate_vulnerability_rule,
        )

        rule = PolicyRule(
            name="no-high", category=RuleCategory.VULNERABILITY,
            severity=RuleSeverity.ERROR, max_severity="HIGH",
        )
        pkg = PackageReport(
            name="vuln-pkg", installed_version="1.0.0",
            vulnerabilities=[
                Vulnerability(vuln_id="CVE-1", summary="RCE", severity="CRITICAL", url=""),
            ],
        )
        result = _evaluate_vulnerability_rule(rule, pkg)
        assert result is not None

    def test_low_vuln_passes_high_threshold(self):
        from depcheck.models import PackageReport, Vulnerability
        from depcheck.policy import (
            PolicyRule,
            RuleCategory,
            RuleSeverity,
            _evaluate_vulnerability_rule,
        )

        rule = PolicyRule(
            name="no-critical-only", category=RuleCategory.VULNERABILITY,
            severity=RuleSeverity.ERROR, max_severity="CRITICAL",
        )
        pkg = PackageReport(
            name="low-vuln-pkg", installed_version="1.0.0",
            vulnerabilities=[
                Vulnerability(vuln_id="CVE-1", summary="XSS", severity="LOW", url=""),
            ],
        )
        result = _evaluate_vulnerability_rule(rule, pkg)
        assert result is None


class TestEvaluatePinningRule:
    """Tests for _evaluate_pinning_rule function."""

    def test_pinned_passes(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_pinning_rule

        rule = PolicyRule(
            name="pin-deps", category=RuleCategory.PINNING,
            severity=RuleSeverity.ERROR, require_pinned=True,
        )
        pkg = PackageReport(name="pinned-pkg", installed_version="1.2.3")
        result = _evaluate_pinning_rule(rule, pkg)
        assert result is None

    def test_unpinned_fails(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_pinning_rule

        rule = PolicyRule(
            name="pin-deps", category=RuleCategory.PINNING,
            severity=RuleSeverity.ERROR, require_pinned=True,
        )
        pkg = PackageReport(name="unpinned-pkg", installed_version="unknown")
        result = _evaluate_pinning_rule(rule, pkg)
        assert result is not None


class TestEvaluateVersionRule:
    """Tests for _evaluate_version_rule function."""

    def test_version_above_minimum(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_version_rule

        rule = PolicyRule(
            name="min-ver", category=RuleCategory.VERSION,
            severity=RuleSeverity.ERROR,
            require_version_min={"test-pkg": "2.0.0"},
        )
        pkg = PackageReport(name="test-pkg", installed_version="3.0.0")
        result = _evaluate_version_rule(rule, pkg)
        assert result is None

    def test_version_below_minimum(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_version_rule

        rule = PolicyRule(
            name="min-ver", category=RuleCategory.VERSION,
            severity=RuleSeverity.ERROR,
            require_version_min={"test-pkg": "2.0.0"},
        )
        pkg = PackageReport(name="test-pkg", installed_version="1.0.0")
        result = _evaluate_version_rule(rule, pkg)
        assert result is not None


class TestEvaluatePackageRule:
    """Tests for _evaluate_package_rule function."""

    def test_deny_list(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_package_rule

        rule = PolicyRule(
            name="deny-pkg", category=RuleCategory.CUSTOM,
            severity=RuleSeverity.ERROR, deny_packages=["bad-pkg"],
        )
        pkg = PackageReport(name="bad-pkg", installed_version="1.0.0")
        result = _evaluate_package_rule(rule, pkg)
        assert result is not None

    def test_allow_list(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_package_rule

        rule = PolicyRule(
            name="allow-pkg", category=RuleCategory.CUSTOM,
            severity=RuleSeverity.ERROR, allow_packages=["good-pkg"],
        )
        pkg = PackageReport(name="other-pkg", installed_version="1.0.0")
        result = _evaluate_package_rule(rule, pkg)
        assert result is not None

    def test_allow_list_passes(self):
        from depcheck.models import PackageReport
        from depcheck.policy import PolicyRule, RuleCategory, RuleSeverity, _evaluate_package_rule

        rule = PolicyRule(
            name="allow-pkg", category=RuleCategory.CUSTOM,
            severity=RuleSeverity.ERROR, allow_packages=["good-pkg"],
        )
        pkg = PackageReport(name="good-pkg", installed_version="1.0.0")
        result = _evaluate_package_rule(rule, pkg)
        assert result is None


class TestEvaluatePolicy:
    """Tests for evaluate_policy function."""

    def test_nonexistent_path(self):
        from depcheck.policy import evaluate_policy

        report = evaluate_policy("/nonexistent/path")
        assert report.errors

    def test_default_rules_with_mock(self):
        from depcheck.models import HealthStatus, PackageReport, ScanResult
        from depcheck.policy import evaluate_policy

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("depcheck.policy.scan_project") as mock_scan:
            mock_scan.return_value = ScanResult(
                project_path=tmpdir,
                packages=[
                    PackageReport(name="pkg-a", installed_version="1.0.0", status=HealthStatus.HEALTHY),  # noqa: E501
                ],
                errors=[],
            )
            report = evaluate_policy(tmpdir)
            assert report.total_packages == 1

    def test_custom_config_with_mock(self):
        from depcheck.models import HealthStatus, LicenseInfo, PackageReport, ScanResult
        from depcheck.policy import (
            PolicyConfig,
            PolicyRule,
            RuleCategory,
            RuleSeverity,
            evaluate_policy,
        )

        config = PolicyConfig(rules=[
            PolicyRule(
                name="no-gpl", category=RuleCategory.LICENSE,
                severity=RuleSeverity.ERROR, deny_copyleft=True,
            ),
        ])

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("depcheck.policy.scan_project") as mock_scan:
            mock_scan.return_value = ScanResult(
                project_path=tmpdir,
                packages=[
                    PackageReport(
                        name="gpl-pkg", installed_version="1.0.0",
                        status=HealthStatus.HEALTHY,
                        license_info=LicenseInfo(spdx_id="GPL-3.0", category="copyleft"),
                    ),
                ],
                errors=[],
            )
            report = evaluate_policy(tmpdir, config=config)
            assert not report.is_compliant
            assert report.error_count > 0


class TestDefaultRules:
    """Tests for _default_rules function."""

    def test_default_rules_exist(self):
        from depcheck.policy import _default_rules

        rules = _default_rules()
        assert len(rules) >= 2
        names = {r.name for r in rules}
        assert "no-critical-vulns" in names
        assert "no-unmaintained" in names


# ─── CLI Integration Tests ─────────────────────────────────────────────────


class TestCLICommands:
    """Tests for CLI command registration."""

    def test_budget_command_exists(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["budget", "--help"])
        assert result.exit_code == 0
        assert "budget" in result.output.lower()

    def test_risks_command_exists(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["risks", "--help"])
        assert result.exit_code == 0
        assert "risk" in result.output.lower()

    def test_advisories_command_exists(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["advisories", "--help"])
        assert result.exit_code == 0
        assert "advisori" in result.output.lower()

    def test_graph_command_exists(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["graph", "--help"])
        assert result.exit_code == 0
        assert "graph" in result.output.lower()

    def test_policy_command_exists(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["policy", "--help"])
        assert result.exit_code == 0
        assert "policy" in result.output.lower()

    def test_main_help_lists_commands(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "budget" in result.output
        assert "risks" in result.output
        assert "advisories" in result.output
        assert "graph" in result.output
        assert "policy" in result.output

    def test_budget_command_options(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["budget", "--help"])
        assert "--json" in result.output
        assert "--max-packages" in result.output
        assert "--max-download-kb" in result.output

    def test_risks_command_options(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["risks", "--help"])
        assert "--json" in result.output
        assert "--severity-threshold" in result.output

    def test_advisories_command_options(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["advisories", "--help"])
        assert "--source" in result.output
        assert "--severity" in result.output
        assert "--patched-only" in result.output
        assert "--unpatched-only" in result.output

    def test_graph_command_options(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["graph", "--help"])
        assert "--max-depth" in result.output
        assert "--max-depth" in result.output
        assert "--check-licenses" in result.output

    def test_policy_command_options(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["policy", "--help"])
        assert "--no-vulns" in result.output
        assert "--no-licenses" in result.output
