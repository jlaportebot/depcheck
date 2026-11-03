"""Tests for depcheck cigate module."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from depcheck.cigate import CIGateResult, determine_gate_exit_code, run_ci_gate
from depcheck.models import HealthStatus, PackageReport, ScanResult, Vulnerability


class TestRunCIGate:
    """Tests for run_ci_gate function."""

    def create_mock_scan_result(self) -> ScanResult:
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

    def test_run_ci_gate_pass(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a minimal pyproject.toml
            Path(tmpdir).joinpath("pyproject.toml").write_text(
                '[project]\nname = "test"\nversion = "0.1.0"\n'
            )
            with patch("depcheck.cigate.scan_project") as mock_scan:
                mock_scan.return_value = ScanResult(
                    project_path=tmpdir,
                    packages=[
                        PackageReport(
                            name="requests",
                            installed_version="2.31.0",
                            latest_version="2.31.0",
                            status=HealthStatus.HEALTHY,
                        ),
                    ],
                )
                result = run_ci_gate(tmpdir, check_vulnerabilities=True, check_licenses=False)
                assert result.verdict == "pass"
                assert "vulnerabilities" in result.passed_checks or "scan" in " ".join(
                    result.passed_checks
                )

    def test_run_ci_gate_fail_vulnerable(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir).joinpath("pyproject.toml").write_text(
                '[project]\nname = "test"\nversion = "0.1.0"\n'
            )
            with patch("depcheck.cigate.scan_project") as mock_scan:
                mock_scan.return_value = self.create_mock_scan_result()
                result = run_ci_gate(
                    tmpdir,
                    check_vulnerabilities=True,
                    check_licenses=False,
                    fail_on="vulnerable",
                )
                assert result.verdict == "fail"
                assert any("vulnerable" in c for c in result.failed_checks)

    def test_run_ci_gate_fail_outdated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir).joinpath("pyproject.toml").write_text(
                '[project]\nname = "test"\nversion = "0.1.0"\n'
            )
            with patch("depcheck.cigate.scan_project") as mock_scan:
                mock_scan.return_value = self.create_mock_scan_result()
                result = run_ci_gate(
                    tmpdir,
                    check_vulnerabilities=True,
                    check_licenses=False,
                    fail_on="outdated",
                )
                assert result.verdict == "fail"
                assert any("outdated" in c for c in result.failed_checks)

    def test_run_ci_gate_enforce_budget(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir).joinpath("pyproject.toml").write_text(
                """[project]
name = "test"
version = "0.1.0"

[tool.depcheck.budget]
total = 2
"""
            )
            with patch("depcheck.cigate.scan_project") as mock_scan:
                mock_scan.return_value = self.create_mock_scan_result()
                with patch("depcheck.cigate.check_budget") as mock_budget:
                    from depcheck.budget import BudgetCategory, BudgetConfig, BudgetReport

                    mock_budget.return_value = BudgetReport(
                        project_path=tmpdir,
                        config=BudgetConfig(total=2),
                        categories=[
                            BudgetCategory(name="total", limit=2, count=3, packages=["a", "b", "c"])
                        ],
                        total_deps=3,
                    )
                    result = run_ci_gate(tmpdir, enforce_budget=True)
                    assert result.verdict == "fail"
                    assert any("budget" in c for c in result.failed_checks)
                    assert result.budget_report is not None

    def test_run_ci_gate_enforce_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir).joinpath("pyproject.toml").write_text(
                """[project]
name = "test"
version = "0.1.0"

[tool.depcheck.policy.vulnerability]
max_severity = "HIGH"
severity = "error"
"""
            )
            with patch("depcheck.cigate.scan_project") as mock_scan:
                mock_scan.return_value = self.create_mock_scan_result()
                with patch("depcheck.cigate.evaluate_policy") as mock_policy:
                    from depcheck.policy import (
                        PolicyReport,
                        RuleCategory,
                        RuleSeverity,
                        Violation,
                    )

                    mock_policy.return_value = PolicyReport(
                        project_path=tmpdir,
                        violations=[
                            Violation(
                                rule_name="vulnerability-policy",
                                package="django",
                                version="4.1.0",
                                severity=RuleSeverity.ERROR,
                                category=RuleCategory.VULNERABILITY,
                                message="High severity vuln",
                            )
                        ],
                        error_count=1,
                        total_packages=3,
                    )
                    result = run_ci_gate(tmpdir, enforce_policy=True)
                    assert result.verdict == "fail"
                    assert any("policy" in c for c in result.failed_checks)
                    assert result.policy_report is not None

    def test_run_ci_gate_missing_config_handles_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # No pyproject.toml
            with patch("depcheck.cigate.scan_project") as mock_scan:
                mock_scan.return_value = ScanResult(
                    project_path=tmpdir,
                    packages=[
                        PackageReport(
                            name="requests",
                            installed_version="2.31.0",
                            latest_version="2.31.0",
                            status=HealthStatus.HEALTHY,
                        ),
                    ],
                )
                result = run_ci_gate(tmpdir, enforce_budget=True, enforce_policy=True)
                # Should not crash, just record errors
                assert result.verdict in ("pass", "fail", "error")
                # Errors should be captured, not raised

    def test_run_ci_gate_scan_error_handles_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("depcheck.cigate.scan_project") as mock_scan:
                mock_scan.return_value = ScanResult(
                    project_path=tmpdir,
                    errors=["Failed to connect to PyPI"],
                )
                result = run_ci_gate(tmpdir)
                assert result.verdict == "error"
                assert len(result.errors) > 0

    def test_run_ci_gate_result_to_dict(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            Path(tmpdir).joinpath("pyproject.toml").write_text(
                '[project]\nname = "test"\nversion = "0.1.0"\n'
            )
            with patch("depcheck.cigate.scan_project") as mock_scan:
                mock_scan.return_value = ScanResult(
                    project_path=tmpdir,
                    packages=[
                        PackageReport(
                            name="requests",
                            installed_version="2.31.0",
                            latest_version="2.31.0",
                            status=HealthStatus.HEALTHY,
                        ),
                    ],
                )
                result = run_ci_gate(tmpdir)
                d = result.to_dict()
                assert d["project_path"] == str(Path(tmpdir).resolve())
                assert d["verdict"] in ("pass", "fail", "error")
                assert "failed_checks" in d
                assert "passed_checks" in d
                assert "scan_result" in d
                assert "summary" in d


class TestDetermineGateExitCode:
    """Tests for determine_gate_exit_code function."""

    def test_pass_returns_zero(self) -> None:
        result = CIGateResult(
            project_path="/test",
            verdict="pass",
            failed_checks=[],
            passed_checks=["scan"],
            scan_result=ScanResult(project_path="/test"),
            summary="All checks passed",
        )
        assert determine_gate_exit_code(result) == 0

    def test_fail_returns_one(self) -> None:
        result = CIGateResult(
            project_path="/test",
            verdict="fail",
            failed_checks=["vulnerabilities"],
            passed_checks=[],
            scan_result=ScanResult(project_path="/test"),
            summary="Vulnerabilities found",
        )
        assert determine_gate_exit_code(result) == 1

    def test_error_returns_two(self) -> None:
        result = CIGateResult(
            project_path="/test",
            verdict="error",
            failed_checks=[],
            passed_checks=[],
            scan_result=ScanResult(project_path="/test", errors=["Config error"]),
            summary="Config error",
        )
        assert determine_gate_exit_code(result) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
