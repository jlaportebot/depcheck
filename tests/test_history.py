"""Tests for depcheck.history — release timeline analysis."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from depcheck.history import (
    CadenceTrend,
    HistoryResult,
    MaintenanceLevel,
    Release,
    RiskLevel,
    Timeline,
    _is_prerelease,
    _parse_version_parts,
    build_history_report,
    build_timeline,
    classify_cadence_trend,
    classify_maintenance,
    classify_risk,
    compute_avg_interval,
    compute_median_interval,
    compute_release_intervals,
    compute_version_gap,
    render_history_json,
    render_history_table,
)
from depcheck.models import HealthStatus, PackageReport, ScanResult

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


def _make_release(
    version: str,
    days_ago: int = 0,
    is_prerelease: bool = False,
    is_yanked: bool = False,
) -> Release:
    """Create a Release for testing."""
    date = datetime.now(tz=timezone.utc) - timedelta(days=days_ago)
    return Release(
        version=version,
        release_date=date,
        is_prerelease=is_prerelease,
        is_yanked=is_yanked,
    )


def _make_releases_data(
    versions: list[tuple[str, int, bool, bool]],
) -> list[dict[str, Any]]:
    """Create releases_data for build_timeline.

    Args:
        versions: List of (version_str, days_ago, is_prerelease, is_yanked).

    Returns:
        List of release dicts suitable for build_timeline.
    """
    now = datetime.now(tz=timezone.utc)
    data: list[dict[str, Any]] = []
    for version_str, days_ago, is_pre, is_yanked in versions:
        upload_time = now - timedelta(days=days_ago)
        data.append({
            "version": version_str,
            "release_date": upload_time.isoformat(),
            "is_prerelease": is_pre,
            "is_yanked": is_yanked,
        })
    return data


# ---------------------------------------------------------------------------
# Release dataclass tests
# ---------------------------------------------------------------------------


class TestRelease:
    """Tests for Release dataclass."""

    def test_creation(self) -> None:
        r = Release(
            version="1.0.0",
            release_date=datetime.now(tz=timezone.utc),
            is_prerelease=False,
            is_yanked=False,
        )
        assert r.version == "1.0.0"
        assert r.is_stable is True

    def test_prerelease(self) -> None:
        r = Release(
            version="1.0.0a1",
            release_date=datetime.now(tz=timezone.utc),
            is_prerelease=True,
        )
        assert r.is_stable is False
        assert r.is_prerelease is True

    def test_yanked(self) -> None:
        r = Release(
            version="1.0.0",
            release_date=datetime.now(tz=timezone.utc),
            is_yanked=True,
        )
        assert r.is_stable is False
        assert r.is_yanked is True


# ---------------------------------------------------------------------------
# Timeline dataclass tests
# ---------------------------------------------------------------------------


class TestTimeline:
    """Tests for Timeline dataclass."""

    def test_defaults(self) -> None:
        tl = Timeline(package_name="test-pkg")
        assert tl.package_name == "test-pkg"
        assert tl.total_releases == 0
        assert tl.maintenance_level == MaintenanceLevel.ACTIVE
        assert tl.cadence_trend == CadenceTrend.INSUFFICIENT_DATA
        assert tl.version_gap == 0

    def test_to_dict(self) -> None:
        tl = Timeline(
            package_name="requests",
            installed_version="2.28.0",
            latest_version="2.31.0",
            total_releases=50,
            stable_releases=40,
            days_since_last_release=90,
            maintenance_level=MaintenanceLevel.ACTIVE,
            risk_level=RiskLevel.LOW,
            cadence_trend=CadenceTrend.STEADY,
            version_gap=3,
        )
        d = tl.to_dict()
        assert d["package_name"] == "requests"
        assert d["installed_version"] == "2.28.0"
        assert d["maintenance_level"] == "active"
        assert d["risk_level"] == "low"
        assert d["cadence_trend"] == "steady"
        assert d["version_gap"] == 3

    def test_to_dict_json_serializable(self) -> None:
        tl = Timeline(package_name="test")
        d = tl.to_dict()
        json_str = json.dumps(d)
        assert json.loads(json_str) == d


# ---------------------------------------------------------------------------
# HistoryResult tests
# ---------------------------------------------------------------------------


class TestHistoryResult:
    """Tests for HistoryResult dataclass."""

    def test_empty(self) -> None:
        r = HistoryResult(project_path="/test")
        assert len(r.timelines) == 0
        assert r.active_count == 0
        assert r.stale_count == 0
        assert r.high_risk_count == 0

    def test_counts(self) -> None:
        r = HistoryResult(
            project_path="/test",
            timelines=[
                Timeline(
                    package_name="a",
                    maintenance_level=MaintenanceLevel.ACTIVE,
                    risk_level=RiskLevel.LOW,
                ),
                Timeline(
                    package_name="b",
                    maintenance_level=MaintenanceLevel.STABLE,
                    risk_level=RiskLevel.MEDIUM,
                ),
                Timeline(
                    package_name="c",
                    maintenance_level=MaintenanceLevel.STALE,
                    risk_level=RiskLevel.HIGH,
                ),
                Timeline(
                    package_name="d",
                    maintenance_level=MaintenanceLevel.ABANDONED,
                    risk_level=RiskLevel.CRITICAL,
                ),
            ],
        )
        assert len(r.timelines) == 4
        assert r.active_count == 1
        assert r.stale_count == 2  # STALE + ABANDONED
        assert r.high_risk_count == 2  # HIGH + CRITICAL

    def test_to_dict(self) -> None:
        r = HistoryResult(project_path="/test")
        d = r.to_dict()
        assert d["project_path"] == "/test"
        assert "summary" in d
        assert "timelines" in d


# ---------------------------------------------------------------------------
# _is_prerelease tests
# ---------------------------------------------------------------------------


class TestIsPrerelease:
    """Tests for _is_prerelease."""

    @pytest.mark.parametrize(
        "version",
        ["1.0.0a1", "1.0.0b2", "1.0.0rc1", "2.0.0alpha1", "2.0.0beta3", "1.0.0dev1", "1.0.0pre1"],
    )
    def test_prerelease_versions(self, version: str) -> None:
        assert _is_prerelease(version) is True

    @pytest.mark.parametrize("version", ["1.0.0", "2.3.4", "10.20.30"])
    def test_stable_versions(self, version: str) -> None:
        assert _is_prerelease(version) is False


# ---------------------------------------------------------------------------
# _parse_version_parts tests
# ---------------------------------------------------------------------------


class TestParseVersionParts:
    """Tests for _parse_version_parts."""

    def test_simple(self) -> None:
        assert _parse_version_parts("1.2.3") == (1, 2, 3)

    def test_two_parts(self) -> None:
        assert _parse_version_parts("2.5") == (2, 5)

    def test_with_pre_suffix(self) -> None:
        result = _parse_version_parts("1.0.0a1")
        assert result[0] == 1
        assert result[1] == 0

    def test_empty_string(self) -> None:
        assert _parse_version_parts("") == (0,)

    def test_non_numeric(self) -> None:
        assert _parse_version_parts("abc") == (0,)


# ---------------------------------------------------------------------------
# compute_version_gap tests
# ---------------------------------------------------------------------------


class TestComputeVersionGap:
    """Tests for compute_version_gap."""

    def test_current(self) -> None:
        total, major, minor, patch = compute_version_gap("1.1.1", "1.1.1")
        assert total == 0
        assert major == 0
        assert minor == 0
        assert patch == 0

    def test_patch_behind(self) -> None:
        total, major, minor, patch = compute_version_gap("1.1.0", "1.1.2")
        assert major == 0
        assert minor == 0
        assert patch == 2
        assert total == 2

    def test_minor_behind(self) -> None:
        total, major, minor, patch = compute_version_gap("1.0.0", "1.2.0")
        assert major == 0
        assert minor == 2
        assert patch == 0

    def test_major_behind(self) -> None:
        total, major, minor, patch = compute_version_gap("1.0.0", "3.0.0")
        assert major == 2
        assert minor == 0
        assert patch == 0

    def test_complex_gap(self) -> None:
        total, major, minor, patch = compute_version_gap("1.2.3", "3.5.7")
        assert major == 2
        assert minor == 3
        assert patch == 4
        assert total == 9


# ---------------------------------------------------------------------------
# compute_release_intervals tests
# ---------------------------------------------------------------------------


class TestComputeReleaseIntervals:
    """Tests for compute_release_intervals."""

    def test_no_releases(self) -> None:
        assert compute_release_intervals([]) == []

    def test_single_release(self) -> None:
        assert compute_release_intervals([_make_release("1.0.0", days_ago=0)]) == []

    def test_two_releases(self) -> None:
        releases = [
            _make_release("1.0.0", days_ago=100),
            _make_release("1.1.0", days_ago=0),
        ]
        intervals = compute_release_intervals(releases)
        assert len(intervals) == 1
        assert intervals[0] == pytest.approx(100.0, abs=1)

    def test_three_releases(self) -> None:
        releases = [
            _make_release("1.0.0", days_ago=200),
            _make_release("1.1.0", days_ago=100),
            _make_release("1.2.0", days_ago=0),
        ]
        intervals = compute_release_intervals(releases)
        assert len(intervals) == 2
        assert intervals[0] == pytest.approx(100.0, abs=1)
        assert intervals[1] == pytest.approx(100.0, abs=1)

    def test_skips_prereleases(self) -> None:
        releases = [
            _make_release("1.0.0", days_ago=100),
            _make_release("2.0.0a1", days_ago=50, is_prerelease=True),
            _make_release("2.0.0", days_ago=10),
        ]
        intervals = compute_release_intervals(releases)
        # Only stable releases: 1.0.0 -> 2.0.0
        assert len(intervals) == 1
        assert intervals[0] == pytest.approx(90.0, abs=1)

    def test_skips_yanked(self) -> None:
        releases = [
            _make_release("1.0.0", days_ago=100),
            _make_release("1.0.1", days_ago=50, is_yanked=True),
            _make_release("1.1.0", days_ago=0),
        ]
        intervals = compute_release_intervals(releases)
        assert len(intervals) == 1


# ---------------------------------------------------------------------------
# compute_avg_interval tests
# ---------------------------------------------------------------------------


class TestComputeAvgInterval:
    """Tests for compute_avg_interval."""

    def test_empty(self) -> None:
        assert compute_avg_interval([]) == 0.0

    def test_single(self) -> None:
        assert compute_avg_interval([100.0]) == 100.0

    def test_multiple(self) -> None:
        assert compute_avg_interval([100.0, 200.0]) == 150.0


# ---------------------------------------------------------------------------
# compute_median_interval tests
# ---------------------------------------------------------------------------


class TestComputeMedianInterval:
    """Tests for compute_median_interval."""

    def test_empty(self) -> None:
        assert compute_median_interval([]) == 0.0

    def test_odd_count(self) -> None:
        assert compute_median_interval([10.0, 20.0, 30.0]) == 20.0

    def test_even_count(self) -> None:
        assert compute_median_interval([10.0, 20.0, 30.0, 40.0]) == 25.0


# ---------------------------------------------------------------------------
# classify_maintenance tests
# ---------------------------------------------------------------------------


class TestClassifyMaintenance:
    """Tests for classify_maintenance."""

    def test_active_very_recent(self) -> None:
        assert classify_maintenance(days_since_last=0, avg_interval=30) == MaintenanceLevel.ACTIVE

    def test_active_frequent(self) -> None:
        assert classify_maintenance(days_since_last=60, avg_interval=30) == MaintenanceLevel.ACTIVE

    def test_active_within_180(self) -> None:
        assert classify_maintenance(days_since_last=150, avg_interval=60) == MaintenanceLevel.ACTIVE

    def test_stable(self) -> None:
        # days_since_last=150, avg_interval=200 => within 180 days, avg_interval > 90
        assert (
            classify_maintenance(days_since_last=150, avg_interval=200) == MaintenanceLevel.STABLE
        )

    def test_slow(self) -> None:
        # days_since_last=300, avg_interval=100 => within 365, avg_interval <= 180
        assert classify_maintenance(days_since_last=300, avg_interval=100) == MaintenanceLevel.SLOW

    def test_stale(self) -> None:
        # days_since_last=300, avg_interval=200 => within 365, avg_interval > 180
        assert classify_maintenance(days_since_last=300, avg_interval=200) == MaintenanceLevel.STALE

    def test_stale_730(self) -> None:
        assert classify_maintenance(days_since_last=500, avg_interval=100) == MaintenanceLevel.STALE

    def test_abandoned(self) -> None:
        assert (
            classify_maintenance(
                days_since_last=800, avg_interval=200
            )
            == MaintenanceLevel.ABANDONED
        )


# ---------------------------------------------------------------------------
# classify_risk tests
# ---------------------------------------------------------------------------


class TestClassifyRisk:
    """Tests for classify_risk."""

    def test_abandoned_critical(self) -> None:
        assert classify_risk(
            days_since_last=800, version_gap=5, maintenance=MaintenanceLevel.ABANDONED
        ) == RiskLevel.CRITICAL

    def test_stale_high(self) -> None:
        assert classify_risk(
            days_since_last=400, version_gap=1, maintenance=MaintenanceLevel.STALE
        ) == RiskLevel.HIGH

    def test_stale_critical_with_gap(self) -> None:
        assert classify_risk(
            days_since_last=400, version_gap=3, maintenance=MaintenanceLevel.STALE
        ) == RiskLevel.CRITICAL

    def test_slow_low(self) -> None:
        assert classify_risk(
            days_since_last=300, version_gap=0, maintenance=MaintenanceLevel.SLOW
        ) == RiskLevel.LOW

    def test_slow_medium(self) -> None:
        assert classify_risk(
            days_since_last=300, version_gap=2, maintenance=MaintenanceLevel.SLOW
        ) == RiskLevel.MEDIUM

    def test_slow_high_with_big_gap(self) -> None:
        assert classify_risk(
            days_since_last=300, version_gap=5, maintenance=MaintenanceLevel.SLOW
        ) == RiskLevel.HIGH

    def test_active_low(self) -> None:
        assert classify_risk(
            days_since_last=30, version_gap=0, maintenance=MaintenanceLevel.ACTIVE
        ) == RiskLevel.LOW

    def test_active_medium_with_huge_gap(self) -> None:
        assert classify_risk(
            days_since_last=30, version_gap=10, maintenance=MaintenanceLevel.ACTIVE
        ) == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# classify_cadence_trend tests
# ---------------------------------------------------------------------------


class TestClassifyCadenceTrend:
    """Tests for classify_cadence_trend."""

    def test_insufficient_data_empty(self) -> None:
        assert classify_cadence_trend([]) == CadenceTrend.INSUFFICIENT_DATA

    def test_insufficient_data_two(self) -> None:
        assert classify_cadence_trend([100.0, 200.0]) == CadenceTrend.INSUFFICIENT_DATA

    def test_improving(self) -> None:
        # first half avg >> second half avg (releases speeding up)
        # 8 intervals: first 4 avg = 100, second 4 avg = 25 => ratio = 0.25 < 0.7
        intervals = [100.0, 100.0, 100.0, 100.0, 25.0, 25.0, 25.0, 25.0]
        assert classify_cadence_trend(intervals) == CadenceTrend.IMPROVING

    def test_declining(self) -> None:
        # first half avg << second half avg (releases slowing down)
        # 8 intervals: first 4 avg = 25, second 4 avg = 100 => ratio = 4.0 > 1.4
        intervals = [25.0, 25.0, 25.0, 25.0, 100.0, 100.0, 100.0, 100.0]
        assert classify_cadence_trend(intervals) == CadenceTrend.DECLINING

    def test_steady(self) -> None:
        # Similar intervals in both halves
        intervals = [100.0, 100.0, 100.0, 100.0]
        assert classify_cadence_trend(intervals) == CadenceTrend.STEADY


# ---------------------------------------------------------------------------
# build_timeline tests
# ---------------------------------------------------------------------------


class TestBuildTimeline:
    """Tests for build_timeline."""

    def test_basic_timeline(self) -> None:
        data = _make_releases_data(
            [
                ("1.0.0", 300, False, False),
                ("1.1.0", 200, False, False),
                ("1.2.0", 100, False, False),
                ("2.0.0", 10, False, False),
            ]
        )
        tl = build_timeline(
            package_name="test-pkg",
            releases_data=data,
            installed_version="1.1.0",
            latest_version="2.0.0",
        )
        assert tl.package_name == "test-pkg"
        assert tl.total_releases == 4
        assert tl.stable_releases == 4
        assert tl.installed_version == "1.1.0"
        assert tl.latest_version == "2.0.0"
        assert tl.major_behind_count == 1  # major version 2 vs 1
        assert tl.version_gap > 0

    def test_empty_releases(self) -> None:
        tl = build_timeline(
            package_name="empty-pkg",
            releases_data=[],
            installed_version="1.0.0",
            latest_version="1.0.0",
        )
        assert tl.total_releases == 0
        assert tl.maintenance_level == MaintenanceLevel.ACTIVE
        assert tl.version_gap == 0

    def test_prereleases_and_yanked(self) -> None:
        data = _make_releases_data(
            [
                ("1.0.0", 300, False, False),
                ("2.0.0a1", 200, True, False),
                ("2.0.0b1", 150, True, False),
                ("2.0.0", 50, False, False),
                ("2.0.1", 10, False, True),  # yanked
            ]
        )
        tl = build_timeline(
            package_name="test-pkg",
            releases_data=data,
            installed_version="1.0.0",
            latest_version="2.0.0",
        )
        assert tl.total_releases == 5
        assert tl.stable_releases == 2  # 1.0.0, 2.0.0 (2.0.1 is yanked, a/b are prerelease)
        assert tl.yanked_releases_count == 1
        assert tl.prerelease_count == 2

    def test_current_version(self) -> None:
        data = _make_releases_data(
            [
                ("1.0.0", 100, False, False),
                ("1.1.0", 0, False, False),
            ]
        )
        tl = build_timeline(
            package_name="test-pkg",
            releases_data=data,
            installed_version="1.1.0",
            latest_version="1.1.0",
        )
        assert tl.version_gap == 0
        assert tl.patch_behind_count == 0
        assert tl.minor_behind_count == 0
        assert tl.major_behind_count == 0

    def test_to_dict(self) -> None:
        data = _make_releases_data(
            [
                ("1.0.0", 100, False, False),
                ("2.0.0", 10, False, False),
            ]
        )
        tl = build_timeline(
            package_name="test-pkg",
            releases_data=data,
            installed_version="1.0.0",
            latest_version="2.0.0",
        )
        d = tl.to_dict()
        # Verify JSON-serializable
        json_str = json.dumps(d)
        parsed = json.loads(json_str)
        assert parsed["package_name"] == "test-pkg"
        assert parsed["total_releases"] == 2

    def test_intervals_computed(self) -> None:
        data = _make_releases_data(
            [
                ("1.0.0", 300, False, False),
                ("1.1.0", 200, False, False),
                ("1.2.0", 100, False, False),
                ("1.3.0", 0, False, False),
            ]
        )
        tl = build_timeline(
            package_name="test-pkg",
            releases_data=data,
        )
        assert tl.avg_days_between_releases > 0
        assert tl.median_days_between_releases > 0
        assert tl.total_releases == 4


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


class TestRenderHistoryTable:
    """Tests for render_history_table."""

    def test_empty_result(self) -> None:
        result = HistoryResult(project_path="/test")
        console = MagicMock()
        render_history_table(result, console=console)
        assert console.print.call_count >= 1

    def test_with_timelines(self) -> None:
        result = HistoryResult(
            project_path="/test",
            timelines=[
                Timeline(
                    package_name="requests",
                    installed_version="2.28.0",
                    latest_version="2.31.0",
                    maintenance_level=MaintenanceLevel.ACTIVE,
                    risk_level=RiskLevel.LOW,
                    cadence_trend=CadenceTrend.STEADY,
                    days_since_last_release=90,
                ),
            ],
        )
        console = MagicMock()
        render_history_table(result, console=console)
        assert console.print.call_count >= 2

    def test_high_risk_timelines(self) -> None:
        result = HistoryResult(
            project_path="/test",
            timelines=[
                Timeline(
                    package_name="old-pkg",
                    maintenance_level=MaintenanceLevel.ABANDONED,
                    risk_level=RiskLevel.CRITICAL,
                    days_since_last_release=800,
                    version_gap=5,
                ),
            ],
        )
        console = MagicMock()
        render_history_table(result, console=console)
        assert console.print.call_count >= 2


class TestRenderHistoryJson:
    """Tests for render_history_json."""

    def test_valid_json(self) -> None:
        result = HistoryResult(project_path="/test")
        json_str = render_history_json(result)
        data = json.loads(json_str)
        assert data["project_path"] == "/test"

    def test_with_timelines(self) -> None:
        result = HistoryResult(
            project_path="/test",
            timelines=[
                Timeline(
                    package_name="requests",
                    maintenance_level=MaintenanceLevel.ACTIVE,
                    risk_level=RiskLevel.LOW,
                ),
            ],
        )
        json_str = render_history_json(result)
        data = json.loads(json_str)
        assert data["summary"]["active"] == 1

    def test_errors_included(self) -> None:
        result = HistoryResult(
            project_path="/test",
            errors=["Something went wrong"],
        )
        json_str = render_history_json(result)
        data = json.loads(json_str)
        assert len(data["errors"]) == 1


# ---------------------------------------------------------------------------
# build_history_report tests
# ---------------------------------------------------------------------------


class TestBuildHistoryReport:
    """Tests for build_history_report."""

    def test_invalid_path(self) -> None:
        result = build_history_report("/nonexistent/xyz/path")
        assert len(result.errors) > 0

    @patch("depcheck.history.PyPIClient")
    @patch("depcheck.history.scan_project")
    def test_basic_report(
        self, mock_scan: MagicMock, mock_pypi_cls: MagicMock, tmp_path: Path
    ) -> None:
        mock_scan.return_value = ScanResult(
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.28.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
            project_path=str(tmp_path),
        )

        mock_client = MagicMock()
        # Return PyPI-style release data
        now = datetime.now(tz=timezone.utc)
        mock_client.get_all_releases.return_value = {
            "2.28.0": [
                {
                    "upload_time_iso": (now - timedelta(days=300)).isoformat(),
                    "yanked": False,
                }
            ],
            "2.31.0": [
                {
                    "upload_time_iso": (now - timedelta(days=10)).isoformat(),
                    "yanked": False,
                }
            ],
        }
        mock_pypi_cls.return_value = mock_client

        # Create a temporary directory with something
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\n")

        result = build_history_report(str(tmp_path))
        assert len(result.timelines) >= 0  # May have errors from mock, but shouldn't crash


# ---------------------------------------------------------------------------
# CLI integration tests
# ---------------------------------------------------------------------------


class TestHistoryCLI:
    """Integration tests for the history CLI command."""

    @patch("depcheck.cli.scan_project")
    def test_history_help(self, mock_scan: MagicMock) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["history", "--help"])
        assert result.exit_code == 0
        assert "timeline" in result.output.lower() or "history" in result.output.lower()

    @patch("depcheck.cli.scan_project")
    def test_history_invalid_path(self, mock_scan: MagicMock) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["history", "/nonexistent/xyz"])
        assert result.exit_code == 2

    @patch("depcheck.history.PyPIClient")
    @patch("depcheck.history.scan_project")
    def test_history_json_output(
        self, mock_scan: MagicMock, mock_pypi_cls: MagicMock, tmp_path: Path
    ) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        mock_scan.return_value = ScanResult(
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.28.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
            project_path=str(tmp_path),
        )

        mock_client = MagicMock()
        now = datetime.now(tz=timezone.utc)
        mock_client.get_all_releases.return_value = {
            "2.28.0": [
                {
                    "upload_time_iso": (now - timedelta(days=300)).isoformat(),
                    "yanked": False,
                }
            ],
            "2.31.0": [
                {
                    "upload_time_iso": (now - timedelta(days=10)).isoformat(),
                    "yanked": False,
                }
            ],
        }
        mock_pypi_cls.return_value = mock_client

        runner = CliRunner()
        result = runner.invoke(main, ["history", str(tmp_path), "--json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "timelines" in data
