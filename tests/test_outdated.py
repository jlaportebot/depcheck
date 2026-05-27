"""Tests for the outdated command and upgrade path analysis."""

from __future__ import annotations

import json
from unittest.mock import patch

from depcheck.models import (
    HealthStatus,
    PackageReport,
    ScanResult,
)
from depcheck.outdated import (
    OutdatedReport,
    RiskLevel,
    UpgradeInfo,
    UpgradeLevel,
    assess_risk,
    build_outdated_report,
    classify_upgrade_level,
    compute_days_behind,
    guess_changelog_url,
    render_outdated_json,
    render_outdated_table,
    render_upgrade_commands,
)

# ── classify_upgrade_level ──────────────────────────────────────────


class TestClassifyUpgradeLevel:
    """Tests for semver-based upgrade classification."""

    def test_patch_upgrade(self):
        assert classify_upgrade_level("1.0.0", "1.0.1") == UpgradeLevel.PATCH

    def test_minor_upgrade(self):
        assert classify_upgrade_level("1.0.0", "1.1.0") == UpgradeLevel.MINOR

    def test_major_upgrade(self):
        assert classify_upgrade_level("1.0.0", "2.0.0") == UpgradeLevel.MAJOR

    def test_major_zero_to_one(self):
        assert classify_upgrade_level("0.9.0", "1.0.0") == UpgradeLevel.MAJOR

    def test_patch_with_micro(self):
        assert classify_upgrade_level("1.2.3", "1.2.4") == UpgradeLevel.PATCH

    def test_minor_same_major(self):
        assert classify_upgrade_level("2.1.0", "2.3.0") == UpgradeLevel.MINOR

    def test_same_version(self):
        # Same version is still "patch" level (no change needed)
        assert classify_upgrade_level("1.0.0", "1.0.0") == UpgradeLevel.PATCH

    def test_prerelease_latest(self):
        assert classify_upgrade_level("1.0.0", "2.0.0a1") == UpgradeLevel.PRERELEASE

    def test_prerelease_dev(self):
        assert classify_upgrade_level("1.0.0", "2.0.0.dev1") == UpgradeLevel.PRERELEASE

    def test_epoch_change_is_major(self):
        assert classify_upgrade_level("1!1.0.0", "2!1.0.0") == UpgradeLevel.MAJOR

    def test_invalid_version(self):
        assert classify_upgrade_level("not-a-version", "also-not") == UpgradeLevel.UNKNOWN

    def test_one_invalid_version(self):
        assert classify_upgrade_level("1.0.0", "not-a-version") == UpgradeLevel.UNKNOWN

    def test_large_version_jump(self):
        assert classify_upgrade_level("1.0.0", "5.0.0") == UpgradeLevel.MAJOR

    def test_multiple_minor_jumps(self):
        assert classify_upgrade_level("1.0.0", "1.5.0") == UpgradeLevel.MINOR


# ── assess_risk ─────────────────────────────────────────────────────


class TestAssessRisk:
    """Tests for risk assessment based on upgrade level and age."""

    def test_major_is_high(self):
        assert assess_risk(UpgradeLevel.MAJOR, None) == RiskLevel.HIGH

    def test_minor_recent_is_medium(self):
        assert assess_risk(UpgradeLevel.MINOR, 30) == RiskLevel.MEDIUM

    def test_minor_old_is_high(self):
        assert assess_risk(UpgradeLevel.MINOR, 400) == RiskLevel.HIGH

    def test_minor_no_days_is_medium(self):
        assert assess_risk(UpgradeLevel.MINOR, None) == RiskLevel.MEDIUM

    def test_patch_is_low(self):
        assert assess_risk(UpgradeLevel.PATCH, None) == RiskLevel.LOW

    def test_patch_old_is_still_low(self):
        assert assess_risk(UpgradeLevel.PATCH, 500) == RiskLevel.LOW

    def test_prerelease_is_high(self):
        assert assess_risk(UpgradeLevel.PRERELEASE, None) == RiskLevel.HIGH

    def test_unknown_level(self):
        assert assess_risk(UpgradeLevel.UNKNOWN, None) == RiskLevel.UNKNOWN

    def test_minor_exactly_365(self):
        assert assess_risk(UpgradeLevel.MINOR, 365) == RiskLevel.MEDIUM

    def test_minor_366_days(self):
        assert assess_risk(UpgradeLevel.MINOR, 366) == RiskLevel.HIGH


# ── compute_days_behind ─────────────────────────────────────────────


class TestComputeDaysBehind:
    """Tests for computing days between release dates."""

    def test_normal_dates(self):
        result = compute_days_behind("2024-01-01", "2024-02-01")
        assert result == 31

    def test_same_date(self):
        result = compute_days_behind("2024-01-01", "2024-01-01")
        assert result == 0

    def test_none_installed(self):
        result = compute_days_behind(None, "2024-01-01")
        assert result is None

    def test_none_latest(self):
        result = compute_days_behind("2024-01-01", None)
        assert result is None

    def test_both_none(self):
        result = compute_days_behind(None, None)
        assert result is None

    def test_invalid_date(self):
        result = compute_days_behind("not-a-date", "2024-01-01")
        assert result is None

    def test_one_year_apart(self):
        result = compute_days_behind("2023-01-01", "2024-01-01")
        assert result == 365


# ── guess_changelog_url ─────────────────────────────────────────────


class TestGuessChangelogUrl:
    """Tests for changelog URL discovery."""

    def test_with_pypi_project_urls(self):
        pypi_info = {
            "info": {
                "project_urls": {
                    "Changelog": "https://example.com/changelog",
                }
            }
        }
        result = guess_changelog_url("requests", pypi_info)
        assert result == "https://example.com/changelog"

    def test_with_history_url(self):
        pypi_info = {
            "info": {
                "project_urls": {
                    "History": "https://example.com/history",
                }
            }
        }
        result = guess_changelog_url("requests", pypi_info)
        assert result == "https://example.com/history"

    def test_with_release_notes_url(self):
        pypi_info = {
            "info": {
                "project_urls": {
                    "Release Notes": "https://example.com/releases",
                }
            }
        }
        result = guess_changelog_url("requests", pypi_info)
        assert result == "https://example.com/releases"

    def test_with_github_homepage(self):
        pypi_info = {
            "info": {
                "home_page": "https://github.com/psf/requests",
            }
        }
        result = guess_changelog_url("requests", pypi_info)
        assert result == "https://github.com/psf/requests/releases"

    def test_without_pypi_info(self):
        result = guess_changelog_url("some-package")
        assert result is not None
        assert "github.com" in result

    def test_empty_pypi_info(self):
        result = guess_changelog_url("some-package", {})
        assert result is not None

    def test_with_changes_key(self):
        pypi_info = {
            "info": {
                "project_urls": {
                    "Changes": "https://example.com/changes",
                }
            }
        }
        result = guess_changelog_url("pkg", pypi_info)
        assert result == "https://example.com/changes"

    def test_no_relevant_project_urls(self):
        pypi_info = {
            "info": {
                "project_urls": {
                    "Homepage": "https://example.com",
                    "Bug Tracker": "https://bugs.example.com",
                }
            }
        }
        result = guess_changelog_url("pkg", pypi_info)
        # Falls back to default pattern
        assert result is not None


# ── build_outdated_report ───────────────────────────────────────────


class TestBuildOutdatedReport:
    """Tests for building OutdatedReport from ScanResult."""

    def _make_scan_result(self, packages: list[PackageReport]) -> ScanResult:
        return ScanResult(
            project_path="/test",
            packages=packages,
            files_scanned=["/test/requirements.txt"],
        )

    def test_empty_scan(self):
        result = self._make_scan_result([])
        report = build_outdated_report(result)
        assert report.total_packages == 0
        assert report.outdated_count == 0
        assert report.up_to_date_count == 0

    def test_all_healthy(self):
        pkgs = [
            PackageReport(name="a", installed_version="1.0.0", latest_version="1.0.0",
                          status=HealthStatus.HEALTHY),
            PackageReport(name="b", installed_version="2.0.0", latest_version="2.0.0",
                          status=HealthStatus.HEALTHY),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        assert report.up_to_date_count == 2
        assert report.outdated_count == 0
        assert len(report.packages) == 0

    def test_outdated_packages(self):
        pkgs = [
            PackageReport(name="old-pkg", installed_version="1.0.0",
                          latest_version="2.0.0", status=HealthStatus.OUTDATED),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        assert report.outdated_count == 1
        assert report.major_count == 1
        assert len(report.packages) == 1
        assert report.packages[0].name == "old-pkg"

    def test_mixed_statuses(self):
        pkgs = [
            PackageReport(name="healthy", installed_version="1.0.0",
                          latest_version="1.0.0", status=HealthStatus.HEALTHY),
            PackageReport(name="outdated", installed_version="1.0.0",
                          latest_version="1.1.0", status=HealthStatus.OUTDATED),
            PackageReport(name="vulnerable", installed_version="1.0.0",
                          latest_version="2.0.0", status=HealthStatus.VULNERABLE),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        assert report.total_packages == 3
        assert report.outdated_count == 1
        assert report.up_to_date_count == 2  # healthy + vulnerable (not outdated type)

    def test_sorting_by_level(self):
        pkgs = [
            PackageReport(name="patch-pkg", installed_version="1.0.0",
                          latest_version="1.0.1", status=HealthStatus.OUTDATED),
            PackageReport(name="major-pkg", installed_version="1.0.0",
                          latest_version="2.0.0", status=HealthStatus.OUTDATED),
            PackageReport(name="minor-pkg", installed_version="1.0.0",
                          latest_version="1.1.0", status=HealthStatus.OUTDATED),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        names = [p.name for p in report.packages]
        assert names == ["major-pkg", "minor-pkg", "patch-pkg"]

    def test_unmaintained_counted_as_outdated(self):
        pkgs = [
            PackageReport(name="unmaintained", installed_version="1.0.0",
                          latest_version="2.0.0", status=HealthStatus.UNMAINTAINED),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        assert report.outdated_count == 1

    def test_unknown_version_skipped(self):
        pkgs = [
            PackageReport(name="no-ver", installed_version="unknown",
                          latest_version="1.0.0", status=HealthStatus.OUTDATED),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        assert report.outdated_count == 0

    def test_errors_propagate(self):
        result = ScanResult(
            project_path="/test",
            errors=["No dependencies found."],
        )
        report = build_outdated_report(result)
        assert "No dependencies found." in report.errors

    def test_with_pypi_infos_for_changelog(self):
        pkgs = [
            PackageReport(name="requests", installed_version="2.28.0",
                          latest_version="2.31.0", status=HealthStatus.OUTDATED),
        ]
        result = self._make_scan_result(pkgs)
        pypi_infos = {
            "requests": {
                "info": {
                    "project_urls": {
                        "Changelog": "https://github.com/psf/requests/blob/main/HISTORY.md",
                    }
                }
            }
        }
        report = build_outdated_report(result, pypi_infos=pypi_infos)
        assert len(report.packages) == 1
        assert "HISTORY.md" in report.packages[0].changelog_url

    def test_minor_upgrade_classification(self):
        pkgs = [
            PackageReport(name="pkg", installed_version="1.0.0",
                          latest_version="1.2.0", status=HealthStatus.OUTDATED),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        assert report.minor_count == 1
        assert report.packages[0].upgrade_level == UpgradeLevel.MINOR

    def test_patch_upgrade_classification(self):
        pkgs = [
            PackageReport(name="pkg", installed_version="1.0.0",
                          latest_version="1.0.5", status=HealthStatus.OUTDATED),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        assert report.patch_count == 1
        assert report.packages[0].upgrade_level == UpgradeLevel.PATCH

    def test_no_latest_version_skipped(self):
        pkgs = [
            PackageReport(name="pkg", installed_version="1.0.0",
                          latest_version=None, status=HealthStatus.OUTDATED),
        ]
        result = self._make_scan_result(pkgs)
        report = build_outdated_report(result)
        assert report.outdated_count == 0


# ── UpgradeInfo.to_dict ─────────────────────────────────────────────


class TestUpgradeInfoToDict:
    """Tests for UpgradeInfo serialization."""

    def test_full_dict(self):
        info = UpgradeInfo(
            name="pkg",
            installed_version="1.0.0",
            latest_version="2.0.0",
            upgrade_level=UpgradeLevel.MAJOR,
            risk=RiskLevel.HIGH,
            days_behind=100,
            latest_release_date="2024-06-01",
            changelog_url="https://example.com/changelog",
        )
        d = info.to_dict()
        assert d["name"] == "pkg"
        assert d["upgrade_level"] == "major"
        assert d["risk"] == "high"
        assert d["days_behind"] == 100

    def test_minimal_dict(self):
        info = UpgradeInfo(name="pkg", installed_version="1.0.0", latest_version="1.1.0")
        d = info.to_dict()
        assert d["name"] == "pkg"
        assert d["days_behind"] is None
        assert d["changelog_url"] is None


# ── OutdatedReport.to_dict ──────────────────────────────────────────


class TestOutdatedReportToDict:
    """Tests for OutdatedReport serialization."""

    def test_empty_report(self):
        report = OutdatedReport()
        d = report.to_dict()
        assert d["summary"]["total_packages"] == 0
        assert d["summary"]["outdated"] == 0
        assert d["packages"] == []

    def test_with_packages(self):
        report = OutdatedReport(
            total_packages=10,
            up_to_date_count=7,
            outdated_count=3,
            major_count=1,
            minor_count=1,
            patch_count=1,
            packages=[
                UpgradeInfo(name="a", installed_version="1.0.0", latest_version="2.0.0",
                            upgrade_level=UpgradeLevel.MAJOR, risk=RiskLevel.HIGH),
            ],
        )
        d = report.to_dict()
        assert d["summary"]["major_upgrades"] == 1
        assert len(d["packages"]) == 1


# ── render_outdated_table ───────────────────────────────────────────


class TestRenderOutdatedTable:
    """Tests for Rich table rendering."""

    def test_empty_report(self, capsys):
        from io import StringIO

        from rich.console import Console

        console = Console(file=StringIO(), force_terminal=False)
        report = OutdatedReport()
        render_outdated_table(report, console=console)
        output = console.file.getvalue()
        assert "up to date" in output.lower()

    def test_with_packages(self):
        from io import StringIO

        from rich.console import Console

        console = Console(file=StringIO(), force_terminal=False)
        report = OutdatedReport(
            total_packages=3,
            outdated_count=2,
            major_count=1,
            minor_count=1,
            patch_count=0,
            up_to_date_count=1,
            packages=[
                UpgradeInfo(name="big-pkg", installed_version="1.0.0",
                            latest_version="2.0.0",
                            upgrade_level=UpgradeLevel.MAJOR, risk=RiskLevel.HIGH),
                UpgradeInfo(name="small-pkg", installed_version="1.0.0",
                            latest_version="1.1.0",
                            upgrade_level=UpgradeLevel.MINOR, risk=RiskLevel.MEDIUM),
            ],
        )
        render_outdated_table(report, console=console)
        output = console.file.getvalue()
        assert "Outdated" in output


# ── render_outdated_json ────────────────────────────────────────────


class TestRenderOutdatedJson:
    """Tests for JSON rendering."""

    def test_valid_json(self):
        report = OutdatedReport(
            total_packages=2,
            outdated_count=1,
            major_count=1,
            packages=[
                UpgradeInfo(name="pkg", installed_version="1.0.0",
                            latest_version="2.0.0",
                            upgrade_level=UpgradeLevel.MAJOR, risk=RiskLevel.HIGH),
            ],
        )
        output = render_outdated_json(report)
        data = json.loads(output)
        assert data["summary"]["total_packages"] == 2
        assert data["summary"]["major_upgrades"] == 1
        assert len(data["packages"]) == 1

    def test_empty_report(self):
        report = OutdatedReport()
        output = render_outdated_json(report)
        data = json.loads(output)
        assert data["summary"]["outdated"] == 0


# ── render_upgrade_commands ─────────────────────────────────────────


class TestRenderUpgradeCommands:
    """Tests for pip upgrade command rendering."""

    def test_no_outdated(self):
        from io import StringIO

        from rich.console import Console

        console = Console(file=StringIO(), force_terminal=False)
        report = OutdatedReport()
        render_upgrade_commands(report, console=console)
        output = console.file.getvalue()
        assert output.strip() == ""

    def test_with_all_risk_levels(self):
        from io import StringIO

        from rich.console import Console

        console = Console(file=StringIO(), force_terminal=False)
        report = OutdatedReport(
            packages=[
                UpgradeInfo(name="patch-pkg", installed_version="1.0.0",
                            latest_version="1.0.1",
                            upgrade_level=UpgradeLevel.PATCH, risk=RiskLevel.LOW),
                UpgradeInfo(name="minor-pkg", installed_version="1.0.0",
                            latest_version="1.1.0",
                            upgrade_level=UpgradeLevel.MINOR, risk=RiskLevel.MEDIUM),
                UpgradeInfo(name="major-pkg", installed_version="1.0.0",
                            latest_version="2.0.0",
                            upgrade_level=UpgradeLevel.MAJOR, risk=RiskLevel.HIGH),
            ],
        )
        render_upgrade_commands(report, console=console)
        output = console.file.getvalue()
        assert "pip install" in output
        assert "patch-pkg" in output
        assert "minor-pkg" in output
        assert "major-pkg" in output


# ── CLI integration ─────────────────────────────────────────────────


class TestOutdatedCLI:
    """Integration tests for the `depcheck outdated` CLI command."""

    def test_outdated_command_registered(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["outdated", "--help"])
        assert result.exit_code == 0
        assert "outdated" in result.output.lower() or "upgrade" in result.output.lower()

    def test_outdated_help_shows_options(self):
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["outdated", "--help"])
        assert "--json" in result.output
        assert "--show-commands" in result.output
        assert "--fail-on" in result.output
        assert "--quiet" in result.output

    @patch("depcheck.cli.scan_project")
    def test_outdated_with_no_packages(self, mock_scan):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path="/test",
            errors=["No dependencies found in the project."],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", "/test"])
        # Should exit with code 2 (error)
        assert result.exit_code == 2

    @patch("depcheck.cli.scan_project")
    def test_outdated_with_healthy_packages(self, mock_scan, tmp_path):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path=str(tmp_path),
            packages=[
                PackageReport(name="pkg", installed_version="1.0.0",
                              latest_version="1.0.0", status=HealthStatus.HEALTHY),
            ],
            files_scanned=[str(tmp_path / "requirements.txt")],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", str(tmp_path)])
        assert result.exit_code == 0

    @patch("depcheck.cli.scan_project")
    def test_outdated_json_output(self, mock_scan, tmp_path):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path=str(tmp_path),
            packages=[
                PackageReport(name="old", installed_version="1.0.0",
                              latest_version="2.0.0", status=HealthStatus.OUTDATED),
            ],
            files_scanned=[str(tmp_path / "requirements.txt")],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", str(tmp_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["outdated"] == 1

    @patch("depcheck.cli.scan_project")
    def test_outdated_fail_on_major(self, mock_scan, tmp_path):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path=str(tmp_path),
            packages=[
                PackageReport(name="pkg", installed_version="1.0.0",
                              latest_version="2.0.0", status=HealthStatus.OUTDATED),
            ],
            files_scanned=[str(tmp_path / "requirements.txt")],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", str(tmp_path), "--fail-on", "major"])
        assert result.exit_code == 1

    @patch("depcheck.cli.scan_project")
    def test_outdated_fail_on_minor_no_major(self, mock_scan, tmp_path):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path=str(tmp_path),
            packages=[
                PackageReport(name="pkg", installed_version="1.0.0",
                              latest_version="1.1.0", status=HealthStatus.OUTDATED),
            ],
            files_scanned=[str(tmp_path / "requirements.txt")],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", str(tmp_path), "--fail-on", "minor"])
        assert result.exit_code == 1

    @patch("depcheck.cli.scan_project")
    def test_outdated_fail_on_major_only_minor(self, mock_scan, tmp_path):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path=str(tmp_path),
            packages=[
                PackageReport(name="pkg", installed_version="1.0.0",
                              latest_version="1.1.0", status=HealthStatus.OUTDATED),
            ],
            files_scanned=[str(tmp_path / "requirements.txt")],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", str(tmp_path), "--fail-on", "major"])
        # Only minor outdated, fail-on major should not trigger
        assert result.exit_code == 0

    @patch("depcheck.cli.scan_project")
    def test_outdated_fail_on_any(self, mock_scan, tmp_path):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path=str(tmp_path),
            packages=[
                PackageReport(name="pkg", installed_version="1.0.0",
                              latest_version="1.0.1", status=HealthStatus.OUTDATED),
            ],
            files_scanned=[str(tmp_path / "requirements.txt")],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", str(tmp_path), "--fail-on", "any"])
        assert result.exit_code == 1

    @patch("depcheck.cli.scan_project")
    def test_outdated_quiet_mode(self, mock_scan, tmp_path):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path=str(tmp_path),
            packages=[
                PackageReport(name="pkg", installed_version="1.0.0",
                              latest_version="1.0.0", status=HealthStatus.HEALTHY),
            ],
            files_scanned=[str(tmp_path / "requirements.txt")],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", str(tmp_path), "--quiet"])
        assert result.exit_code == 0

    @patch("depcheck.cli.scan_project")
    def test_outdated_show_commands(self, mock_scan, tmp_path):
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            project_path=str(tmp_path),
            packages=[
                PackageReport(name="pkg", installed_version="1.0.0",
                              latest_version="1.0.1", status=HealthStatus.OUTDATED),
            ],
            files_scanned=[str(tmp_path / "requirements.txt")],
        )
        runner = CliRunner()
        result = runner.invoke(main, ["outdated", str(tmp_path), "--show-commands"])
        assert result.exit_code == 0
        assert "pip install" in result.output
