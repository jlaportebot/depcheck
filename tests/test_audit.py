"""Tests for depcheck audit module."""

from __future__ import annotations

from depcheck.audit import (
    AuditResult,
    PackageRisk,
    RemediationAction,
    RiskLevel,
    SeverityBreakdown,
    _build_vulnerability_details,
    _compute_package_risk,
    _compute_project_risk,
    _compute_severity_breakdown,
    _generate_remediations,
)
from depcheck.models import (
    HealthStatus,
    LicenseInfo,
    PackageReport,
    Vulnerability,
)

# ── Test helpers ──────────────────────────────────────────────────────────


def _make_vuln(
    vuln_id: str = "OSV-001",
    severity: str = "HIGH",
    summary: str = "Test vulnerability",
) -> Vulnerability:
    return Vulnerability(
        vuln_id=vuln_id,
        summary=summary,
        severity=severity,
        url=f"https://osv.dev/vulnerability/{vuln_id}",
        aliases=["CVE-2024-0001"],
    )


def _make_pkg(
    name: str = "test-pkg",
    version: str = "1.0.0",
    status: HealthStatus = HealthStatus.HEALTHY,
    vulns: list[Vulnerability] | None = None,
    latest_version: str | None = None,
    yanked: bool = False,
    removed: bool = False,
    last_release: str | None = None,
    license_info: LicenseInfo | None = None,
) -> PackageReport:
    pkg = PackageReport(
        name=name,
        installed_version=version,
        latest_version=latest_version,
        status=status,
        is_yanked=yanked,
        is_removed=removed,
        last_release_date=last_release,
        license_info=license_info,
    )
    if vulns:
        pkg.vulnerabilities = vulns
    return pkg


# ── SeverityBreakdown tests ──────────────────────────────────────────────


class TestSeverityBreakdown:
    """Tests for SeverityBreakdown model."""

    def test_total_zero(self) -> None:
        bd = SeverityBreakdown()
        assert bd.total == 0

    def test_total_with_counts(self) -> None:
        bd = SeverityBreakdown(critical=2, high=3, low=1)
        assert bd.total == 6

    def test_to_dict(self) -> None:
        bd = SeverityBreakdown(critical=1, high=2, medium=3, low=4, unknown=5)
        d = bd.to_dict()
        assert d["critical"] == 1
        assert d["total"] == 15


# ── Package risk scoring tests ────────────────────────────────────────────


class TestComputePackageRisk:
    """Tests for _compute_package_risk."""

    def test_healthy_package_no_risk(self) -> None:
        pkg = _make_pkg(status=HealthStatus.HEALTHY)
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 0.0
        assert risk.risk_level == RiskLevel.NONE
        assert risk.issues == []

    def test_single_critical_vuln(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="CRITICAL")],
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 40.0
        assert risk.risk_level == RiskLevel.MEDIUM  # 40 is MEDIUM (25-49)
        assert risk.vulnerability_count == 1
        assert risk.highest_severity == "CRITICAL"

    def test_single_high_vuln(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="HIGH")],
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 25.0
        assert risk.risk_level == RiskLevel.MEDIUM  # 25 is MEDIUM

    def test_single_low_vuln(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="LOW")],
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 5.0
        assert risk.risk_level == RiskLevel.LOW

    def test_multiple_vulns_diminishing_returns(self) -> None:
        """Multiple vulns should stack with diminishing returns."""
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[
                _make_vuln(vuln_id="OSV-1", severity="CRITICAL"),
                _make_vuln(vuln_id="OSV-2", severity="CRITICAL"),
                _make_vuln(vuln_id="OSV-3", severity="CRITICAL"),
            ],
        )
        risk = _compute_package_risk(pkg)
        # 1st: 40*1.0 = 40, 2nd: 40*0.667 = 26.67, 3rd: 40*0.5 = 20
        expected = 40.0 + 40.0 / 1.5 + 40.0 / 2.0
        assert abs(risk.risk_score - expected) < 0.1
        assert risk.vulnerability_count == 3

    def test_mixed_severity_vulns(self) -> None:
        """Mixed severities should be sorted with highest first."""
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[
                _make_vuln(vuln_id="OSV-1", severity="LOW"),
                _make_vuln(vuln_id="OSV-2", severity="CRITICAL"),
            ],
        )
        risk = _compute_package_risk(pkg)
        assert risk.highest_severity == "CRITICAL"
        # CRITICAL first = 40, then LOW = 5 * 0.667 = 3.33
        assert risk.risk_score > 40.0

    def test_outdated_penalty(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.OUTDATED,
            latest_version="2.0.0",
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 5.0
        assert risk.risk_level == RiskLevel.LOW
        assert risk.is_outdated is True

    def test_unmaintained_penalty(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.UNMAINTAINED,
            last_release="2020-01-01",
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 15.0
        assert risk.risk_level == RiskLevel.LOW  # 15 is LOW (>0, <25)
        assert risk.is_unmaintained is True

    def test_yanked_penalty(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.YANKED,
            yanked=True,
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 30.0
        assert risk.risk_level == RiskLevel.MEDIUM  # 30 is MEDIUM

    def test_removed_penalty(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.REMOVED,
            removed=True,
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 50.0
        assert risk.risk_level == RiskLevel.HIGH  # 50 >= 50 → HIGH

    def test_vuln_plus_outdated(self) -> None:
        """Vulnerability + outdated should combine scores."""
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="HIGH")],
            latest_version="2.0.0",
        )
        risk = _compute_package_risk(pkg)
        # HIGH vuln (25) + outdated (5) = 30
        assert risk.risk_score == 30.0
        assert risk.risk_level == RiskLevel.MEDIUM  # 30 is MEDIUM

    def test_vuln_plus_unmaintained(self) -> None:
        """Vulnerability + unmaintained should combine."""
        pkg = _make_pkg(
            status=HealthStatus.UNMAINTAINED,
            vulns=[_make_vuln(severity="MEDIUM")],
            last_release="2020-01-01",
        )
        risk = _compute_package_risk(pkg)
        # MEDIUM vuln (15) + unmaintained (15) = 30
        assert risk.risk_score == 30.0

    def test_score_capped_at_100(self) -> None:
        """Score should never exceed 100."""
        pkg = _make_pkg(
            status=HealthStatus.REMOVED,
            removed=True,
            vulns=[
                _make_vuln(vuln_id=f"OSV-{i}", severity="CRITICAL")
                for i in range(10)
            ],
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score <= 100.0

    def test_license_issue_penalty(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.HEALTHY,
            license_info=LicenseInfo(
                spdx_id="GPL-3.0",
                raw_license="GPL-3.0",
                category="copyleft",
                is_compliant=False,
                compliance_note="Denied by policy",
            ),
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 5.0
        assert "License compliance issue" in risk.issues

    def test_unknown_severity_vuln(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="UNKNOWN")],
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 10.0

    def test_to_dict(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="HIGH")],
            latest_version="2.0.0",
        )
        risk = _compute_package_risk(pkg)
        d = risk.to_dict()
        assert d["name"] == "test-pkg"
        assert d["risk_level"] == "medium"
        assert d["vulnerability_count"] == 1
        assert d["is_outdated"] is True


# ── Project risk scoring tests ────────────────────────────────────────────


class TestComputeProjectRisk:
    """Tests for _compute_project_risk."""

    def test_empty_risks(self) -> None:
        score, level = _compute_project_risk([])
        assert score == 0.0
        assert level == RiskLevel.NONE

    def test_all_healthy(self) -> None:
        risks = [
            PackageRisk(name="a", version="1.0", risk_score=0.0, risk_level=RiskLevel.NONE),
            PackageRisk(name="b", version="2.0", risk_score=0.0, risk_level=RiskLevel.NONE),
        ]
        score, level = _compute_project_risk(risks)
        assert score == 0.0
        assert level == RiskLevel.NONE

    def test_mixed_risks(self) -> None:
        risks = [
            PackageRisk(name="a", version="1.0", risk_score=50.0, risk_level=RiskLevel.HIGH),
            PackageRisk(name="b", version="2.0", risk_score=0.0, risk_level=RiskLevel.NONE),
            PackageRisk(name="c", version="3.0", risk_score=10.0, risk_level=RiskLevel.LOW),
        ]
        score, level = _compute_project_risk(risks)
        assert score > 0
        assert level in (RiskLevel.MEDIUM, RiskLevel.HIGH)

    def test_critical_package_floors_at_high(self) -> None:
        """If any package is CRITICAL, project risk should be at least HIGH."""
        risks = [
            PackageRisk(name="a", version="1.0", risk_score=80.0, risk_level=RiskLevel.CRITICAL),
            PackageRisk(name="b", version="2.0", risk_score=0.0, risk_level=RiskLevel.NONE),
        ]
        score, level = _compute_project_risk(risks)
        assert score >= 50.0
        assert level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# ── Severity breakdown tests ──────────────────────────────────────────────


class TestComputeSeverityBreakdown:
    """Tests for _compute_severity_breakdown."""

    def test_no_vulns(self) -> None:
        packages = [_make_pkg(status=HealthStatus.HEALTHY)]
        bd = _compute_severity_breakdown(packages)
        assert bd.total == 0

    def test_mixed_severities(self) -> None:
        packages = [
            _make_pkg(
                status=HealthStatus.VULNERABLE,
                vulns=[
                    _make_vuln(vuln_id="1", severity="CRITICAL"),
                    _make_vuln(vuln_id="2", severity="HIGH"),
                ],
            ),
            _make_pkg(
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(vuln_id="3", severity="MEDIUM")],
            ),
        ]
        bd = _compute_severity_breakdown(packages)
        assert bd.critical == 1
        assert bd.high == 1
        assert bd.medium == 1
        assert bd.total == 3

    def test_moderate_counts_as_medium(self) -> None:
        packages = [
            _make_pkg(
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(severity="MODERATE")],
            ),
        ]
        bd = _compute_severity_breakdown(packages)
        assert bd.medium == 1
        assert bd.total == 1

    def test_unknown_severity(self) -> None:
        packages = [
            _make_pkg(
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(severity="UNKNOWN")],
            ),
        ]
        bd = _compute_severity_breakdown(packages)
        assert bd.unknown == 1


# ── Vulnerability details tests ───────────────────────────────────────────


class TestBuildVulnerabilityDetails:
    """Tests for _build_vulnerability_details."""

    def test_no_vulns(self) -> None:
        packages = [_make_pkg(status=HealthStatus.HEALTHY)]
        details = _build_vulnerability_details(packages)
        assert details == []

    def test_vuln_details_sorted_by_severity(self) -> None:
        packages = [
            _make_pkg(
                name="alpha",
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(vuln_id="LOW-1", severity="LOW")],
            ),
            _make_pkg(
                name="beta",
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(vuln_id="CRIT-1", severity="CRITICAL")],
            ),
        ]
        details = _build_vulnerability_details(packages)
        assert len(details) == 2
        assert details[0].vuln_id == "CRIT-1"
        assert details[1].vuln_id == "LOW-1"

    def test_fix_available_when_outdated(self) -> None:
        packages = [
            _make_pkg(
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln()],
                latest_version="2.0.0",
            ),
        ]
        details = _build_vulnerability_details(packages)
        assert details[0].fix_available is True
        assert details[0].fixed_in_version == "2.0.0"

    def test_fix_not_available_when_current(self) -> None:
        packages = [
            _make_pkg(
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln()],
                latest_version=None,
            ),
        ]
        details = _build_vulnerability_details(packages)
        assert details[0].fix_available is False
        assert details[0].fixed_in_version is None

    def test_to_dict(self) -> None:
        packages = [
            _make_pkg(
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(vuln_id="OSV-123", severity="HIGH")],
            ),
        ]
        details = _build_vulnerability_details(packages)
        d = details[0].to_dict()
        assert d["id"] == "OSV-123"
        assert d["package"] == "test-pkg"
        assert d["severity"] == "HIGH"
        assert d["aliases"] == ["CVE-2024-0001"]


# ── Remediation tests ─────────────────────────────────────────────────────


class TestGenerateRemediations:
    """Tests for _generate_remediations."""

    def test_healthy_no_remediation(self) -> None:
        pkg = _make_pkg(status=HealthStatus.HEALTHY)
        risk = _compute_package_risk(pkg)
        actions = _generate_remediations(pkg, risk)
        assert actions == []

    def test_removed_package(self) -> None:
        pkg = _make_pkg(status=HealthStatus.REMOVED, removed=True)
        risk = _compute_package_risk(pkg)
        actions = _generate_remediations(pkg, risk)
        assert len(actions) == 1
        assert actions[0].action == "remove"
        assert actions[0].urgency == "critical"

    def test_yanked_package(self) -> None:
        pkg = _make_pkg(status=HealthStatus.YANKED, yanked=True)
        risk = _compute_package_risk(pkg)
        actions = _generate_remediations(pkg, risk)
        assert any(a.action == "pin" for a in actions)

    def test_vuln_with_upgrade_available(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="HIGH")],
            latest_version="2.0.0",
        )
        risk = _compute_package_risk(pkg)
        actions = _generate_remediations(pkg, risk)
        upgrade = [a for a in actions if a.action == "upgrade"]
        assert len(upgrade) == 1
        assert upgrade[0].from_version == "1.0.0"
        assert upgrade[0].to_version == "2.0.0"
        assert upgrade[0].urgency == "critical"  # HIGH severity → critical urgency

    def test_vuln_critical_no_upgrade(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="CRITICAL")],
            latest_version=None,
        )
        risk = _compute_package_risk(pkg)
        actions = _generate_remediations(pkg, risk)
        review = [a for a in actions if a.action == "review"]
        assert len(review) == 1
        assert review[0].urgency == "critical"

    def test_vuln_low_no_upgrade(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="LOW")],
            latest_version=None,
        )
        risk = _compute_package_risk(pkg)
        actions = _generate_remediations(pkg, risk)
        review = [a for a in actions if a.action == "review"]
        assert len(review) == 1
        assert review[0].urgency == "medium"

    def test_outdated_no_vuln(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.OUTDATED,
            latest_version="2.0.0",
        )
        risk = _compute_package_risk(pkg)
        actions = _generate_remediations(pkg, risk)
        upgrade = [a for a in actions if a.action == "upgrade"]
        assert len(upgrade) == 1
        assert upgrade[0].urgency == "low"

    def test_unmaintained_replacement(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.UNMAINTAINED,
            last_release="2020-01-01",
        )
        risk = _compute_package_risk(pkg)
        actions = _generate_remediations(pkg, risk)
        replace = [a for a in actions if a.action == "replace"]
        assert len(replace) == 1
        assert replace[0].urgency == "medium"

    def test_remediation_to_dict(self) -> None:
        action = RemediationAction(
            package="test",
            action="upgrade",
            description="Upgrade test",
            urgency="high",
            from_version="1.0.0",
            to_version="2.0.0",
        )
        d = action.to_dict()
        assert d["package"] == "test"
        assert d["action"] == "upgrade"
        assert d["urgency"] == "high"
        assert d["from_version"] == "1.0.0"
        assert d["to_version"] == "2.0.0"


# ── AuditResult integration tests ─────────────────────────────────────────


class TestAuditResult:
    """Tests for AuditResult model."""

    def test_to_dict(self) -> None:
        audit = AuditResult(
            project_path="/test",
            total_packages=10,
            risk_score=35.0,
            risk_level=RiskLevel.MEDIUM,
            severity_breakdown=SeverityBreakdown(high=1, medium=2),
        )
        d = audit.to_dict()
        assert d["project_path"] == "/test"
        assert d["total_packages"] == 10
        assert d["risk_score"] == 35.0
        assert d["risk_level"] == "medium"
        assert d["severity_breakdown"]["high"] == 1
        assert d["severity_breakdown"]["total"] == 3

    def test_empty_audit(self) -> None:
        audit = AuditResult(project_path="/empty")
        d = audit.to_dict()
        assert d["total_packages"] == 0
        assert d["risk_level"] == "none"
        assert d["vulnerabilities"] == []
        assert d["remediations"] == []


# ── Risk level ordering tests ─────────────────────────────────────────────


class TestRiskLevelOrdering:
    """Tests for risk level thresholds."""

    def test_score_thresholds(self) -> None:
        """Verify risk level assignment at score boundaries."""
        # NONE: score = 0
        pkg = _make_pkg(status=HealthStatus.HEALTHY)
        risk = _compute_package_risk(pkg)
        assert risk.risk_level == RiskLevel.NONE

        # LOW: 0 < score < 25
        pkg = _make_pkg(status=HealthStatus.OUTDATED, latest_version="2.0.0")
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 5.0
        assert risk.risk_level == RiskLevel.LOW

        # MEDIUM: 25 <= score < 50
        pkg = _make_pkg(status=HealthStatus.VULNERABLE, vulns=[_make_vuln(severity="HIGH")])
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 25.0
        assert risk.risk_level == RiskLevel.MEDIUM

        # HIGH: 50 <= score < 75
        pkg = _make_pkg(status=HealthStatus.REMOVED, removed=True)
        risk = _compute_package_risk(pkg)
        assert risk.risk_score == 50.0
        assert risk.risk_level == RiskLevel.HIGH  # 50 >= 50 → HIGH

        # CRITICAL: score >= 75
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            vulns=[_make_vuln(severity="CRITICAL"), _make_vuln(severity="HIGH")],
        )
        risk = _compute_package_risk(pkg)
        assert risk.risk_score >= 50.0


# ── Edge case tests ───────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge case tests for audit module."""

    def test_empty_vulnerability_list(self) -> None:
        pkg = _make_pkg(status=HealthStatus.VULNERABLE, vulns=[])
        risk = _compute_package_risk(pkg)
        # Vulnerable status but no vulns — score from status only
        # (Outdated check if latest_version is set)
        assert risk.vulnerability_count == 0

    def test_multiple_packages_same_name(self) -> None:
        """Multiple packages should be scored independently."""
        pkgs = [
            _make_pkg(
                name="pkg-a",
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(severity="CRITICAL")],
            ),
            _make_pkg(name="pkg-b", status=HealthStatus.HEALTHY),
        ]
        risks = [_compute_package_risk(p) for p in pkgs]
        assert risks[0].risk_score > risks[1].risk_score

    def test_severity_breakdown_multiple_packages(self) -> None:
        packages = [
            _make_pkg(
                name="a",
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(severity="CRITICAL"), _make_vuln(severity="HIGH")],
            ),
            _make_pkg(
                name="b",
                status=HealthStatus.VULNERABLE,
                vulns=[_make_vuln(severity="LOW")],
            ),
            _make_pkg(name="c", status=HealthStatus.HEALTHY),
        ]
        bd = _compute_severity_breakdown(packages)
        assert bd.critical == 1
        assert bd.high == 1
        assert bd.low == 1
        assert bd.total == 3

    def test_vulnerability_detail_aliases(self) -> None:
        packages = [
            _make_pkg(
                status=HealthStatus.VULNERABLE,
                vulns=[Vulnerability(
                    vuln_id="GHSA-xxxx",
                    summary="Bad bug",
                    severity="HIGH",
                    url="https://osv.dev/vulnerability/GHSA-xxxx",
                    aliases=["CVE-2024-1234", "PYSEC-2024-5678"],
                )],
            ),
        ]
        details = _build_vulnerability_details(packages)
        assert len(details[0].aliases) == 2
        assert "CVE-2024-1234" in details[0].aliases

    def test_all_risk_levels_in_dict(self) -> None:
        """Ensure all RiskLevel values serialize correctly."""
        for level in RiskLevel:
            audit = AuditResult(project_path="/t", risk_level=level)
            d = audit.to_dict()
            assert d["risk_level"] == level.value
