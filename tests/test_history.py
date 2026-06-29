"""Tests for depcheck.history — dependency version history analysis."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from io import StringIO
from unittest.mock import MagicMock

import pytest

from depcheck.history import (
    HistoryReport,
    MaintenanceTrend,
    PackageHistory,
    VersionRelease,
    _compute_trend,
    analyze_history,
    analyze_package_history,
    render_history_json,
    render_history_table,
)
from depcheck.models import ParsedDependency

# ---------------------------------------------------------------------------
# VersionRelease tests
# ---------------------------------------------------------------------------


class TestVersionRelease:
    """Tests for the VersionRelease dataclass."""

    def test_to_dict(self) -> None:
        vr = VersionRelease(version="1.0.0", release_date="2024-01-15", is_current=True)
        d = vr.to_dict()
        assert d["version"] == "1.0.0"
        assert d["release_date"] == "2024-01-15"
        assert d["is_current"] is True
        assert d["is_latest"] is False


# ---------------------------------------------------------------------------
# PackageHistory tests
# ---------------------------------------------------------------------------


class TestPackageHistory:
    """Tests for the PackageHistory dataclass."""

    def test_defaults(self) -> None:
        ph = PackageHistory(name="foo", installed_version="1.0")
        assert ph.maintenance_trend == MaintenanceTrend.UNKNOWN
        assert ph.current_version_age_days is None
        assert ph.releases_per_year is None
        assert ph.error is None

    def test_to_dict(self) -> None:
        ph = PackageHistory(
            name="foo",
            installed_version="1.0",
            latest_version="2.0",
            current_version_age_days=100,
            releases_per_year=4.5,
            avg_days_between_releases=80.0,
            maintenance_trend=MaintenanceTrend.STEADY,
            total_releases=10,
            years_active=2.5,
        )
        d = ph.to_dict()
        assert d["name"] == "foo"
        assert d["current_version_age_days"] == 100
        assert d["releases_per_year"] == 4.5
        assert d["maintenance_trend"] == "steady"
        assert d["years_active"] == 2.5

    def test_to_dict_with_none_values(self) -> None:
        ph = PackageHistory(name="foo", installed_version="1.0")
        d = ph.to_dict()
        assert d["releases_per_year"] is None
        assert d["avg_days_between_releases"] is None
        assert d["years_active"] is None

    def test_to_dict_with_error(self) -> None:
        ph = PackageHistory(name="foo", installed_version="1.0", error="not found")
        d = ph.to_dict()
        assert d["error"] == "not found"


# ---------------------------------------------------------------------------
# HistoryReport tests
# ---------------------------------------------------------------------------


class TestHistoryReport:
    """Tests for the HistoryReport dataclass."""

    def _make_report(self) -> HistoryReport:
        packages = [
            PackageHistory(
                name="a",
                installed_version="1.0",
                maintenance_trend=MaintenanceTrend.ACCELERATING,
                current_version_age_days=30,
            ),
            PackageHistory(
                name="b",
                installed_version="2.0",
                maintenance_trend=MaintenanceTrend.STEADY,
                current_version_age_days=60,
            ),
            PackageHistory(
                name="c",
                installed_version="3.0",
                maintenance_trend=MaintenanceTrend.ABANDONED,
                current_version_age_days=800,
            ),
            PackageHistory(
                name="d",
                installed_version="4.0",
                maintenance_trend=MaintenanceTrend.SLOWING,
                current_version_age_days=200,
            ),
            PackageHistory(
                name="e",
                installed_version="5.0",
                maintenance_trend=MaintenanceTrend.NEW,
            ),
            PackageHistory(
                name="f",
                installed_version="6.0",
                maintenance_trend=MaintenanceTrend.UNKNOWN,
            ),
        ]
        return HistoryReport(project_path="/tmp/test", packages=packages)

    def test_counts(self) -> None:
        report = self._make_report()
        assert report.package_count == 6
        assert report.accelerating_count == 1
        assert report.steady_count == 1
        assert report.abandoned_count == 1
        assert report.slowing_count == 1
        assert report.new_count == 1
        assert report.unknown_count == 1

    def test_avg_current_version_age(self) -> None:
        report = self._make_report()
        # Only a, b, c, d have ages: 30, 60, 800, 200
        assert report.avg_current_version_age == pytest.approx(272.5)

    def test_oldest_current_version(self) -> None:
        report = self._make_report()
        assert report.oldest_current_version is not None
        assert report.oldest_current_version.name == "c"

    def test_newest_current_version(self) -> None:
        report = self._make_report()
        assert report.newest_current_version is not None
        assert report.newest_current_version.name == "a"

    def test_empty_report(self) -> None:
        report = HistoryReport(project_path="/tmp")
        assert report.package_count == 0
        assert report.avg_current_version_age is None
        assert report.oldest_current_version is None
        assert report.newest_current_version is None

    def test_to_dict(self) -> None:
        report = self._make_report()
        d = report.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert d["summary"]["package_count"] == 6
        assert d["summary"]["trends"]["accelerating"] == 1
        assert len(d["packages"]) == 6


# ---------------------------------------------------------------------------
# _compute_trend tests
# ---------------------------------------------------------------------------


class TestComputeTrend:
    """Tests for the _compute_trend helper."""

    def test_new_single_release(self) -> None:
        now = datetime.now(tz=timezone.utc)
        dates = [now - timedelta(days=30)]
        assert _compute_trend(dates) == MaintenanceTrend.NEW

    def test_abandoned(self) -> None:
        now = datetime.now(tz=timezone.utc)
        dates = [
            now - timedelta(days=1000),
            now - timedelta(days=800),
            now - timedelta(days=600),
            now - timedelta(days=580),  # Last release 580 days ago
        ]
        assert _compute_trend(dates) == MaintenanceTrend.ABANDONED

    def test_accelerating(self) -> None:
        now = datetime.now(tz=timezone.utc)
        # Need at least 4 releases. First half: large gaps, second half: small gaps
        # ratio = second_avg / first_avg < 0.67 → ACCELERATING
        dates = [
            now - timedelta(days=900),
            now - timedelta(days=800),
            now - timedelta(days=700),
            now - timedelta(days=600),
            # Second half — more frequent (gaps ~20 days vs ~100 days)
            now - timedelta(days=80),
            now - timedelta(days=60),
            now - timedelta(days=40),
            now - timedelta(days=20),
        ]
        result = _compute_trend(dates)
        assert result == MaintenanceTrend.ACCELERATING

    def test_slowing(self) -> None:
        now = datetime.now(tz=timezone.utc)
        # First half: small gaps, second half: large gaps
        # ratio = second_avg / first_avg > 1.5 → SLOWING
        dates = [
            now - timedelta(days=800),
            now - timedelta(days=780),
            now - timedelta(days=760),
            now - timedelta(days=740),
            # Second half — less frequent (gaps ~150 days vs ~20 days)
            now - timedelta(days=500),
            now - timedelta(days=350),
            now - timedelta(days=200),
            now - timedelta(days=10),
        ]
        result = _compute_trend(dates)
        assert result == MaintenanceTrend.SLOWING

    def test_steady(self) -> None:
        now = datetime.now(tz=timezone.utc)
        # Consistent ~100-day gaps (ratio near 1.0)
        dates = [
            now - timedelta(days=700),
            now - timedelta(days=600),
            now - timedelta(days=500),
            now - timedelta(days=400),
            now - timedelta(days=300),
            now - timedelta(days=200),
            now - timedelta(days=100),
            now - timedelta(days=10),
        ]
        result = _compute_trend(dates)
        assert result == MaintenanceTrend.STEADY

    def test_few_releases_steady(self) -> None:
        now = datetime.now(tz=timezone.utc)
        dates = [now - timedelta(days=200), now - timedelta(days=10)]
        assert _compute_trend(dates) == MaintenanceTrend.STEADY

    def test_empty_dates(self) -> None:
        assert _compute_trend([]) == MaintenanceTrend.NEW


# ---------------------------------------------------------------------------
# analyze_package_history tests
# ---------------------------------------------------------------------------


class TestAnalyzePackageHistory:
    """Tests for analyze_package_history."""

    def _make_pypi_response(self) -> dict:
        """Create a mock PyPI API response."""
        now = datetime.now(tz=timezone.utc)
        releases = {}
        for i in range(5):
            dt = now - timedelta(days=(5 - i) * 100)
            ver = f"1.{i}.0"
            releases[ver] = [
                {
                    "upload_time_iso_8601": dt.isoformat(),
                    "packagetype": "sdist",
                }
            ]
        return {
            "info": {"version": "1.4.0"},
            "releases": releases,
        }

    def test_success(self) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = self._make_pypi_response()
        mock_client.get_last_release_date.return_value = datetime.now(tz=timezone.utc)

        dep = ParsedDependency(name="requests", version="1.3.0")
        result = analyze_package_history(dep, mock_client)
        assert result.name == "requests"
        assert result.installed_version == "1.3.0"
        assert result.latest_version == "1.4.0"
        assert result.total_releases == 5
        assert result.current_version_age_days is not None
        assert result.current_version_age_days > 0
        assert result.maintenance_trend != MaintenanceTrend.UNKNOWN

    def test_package_not_found(self) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = None

        dep = ParsedDependency(name="nonexistent", version="1.0")
        result = analyze_package_history(dep, mock_client)
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_no_releases(self) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = {
            "info": {"version": "1.0.0"},
            "releases": {},
        }

        dep = ParsedDependency(name="foo", version="1.0.0")
        result = analyze_package_history(dep, mock_client)
        assert result.error is not None

    def test_exception_handling(self) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.side_effect = Exception("network error")

        dep = ParsedDependency(name="foo", version="1.0")
        result = analyze_package_history(dep, mock_client)
        assert result.error is not None


# ---------------------------------------------------------------------------
# analyze_history integration tests
# ---------------------------------------------------------------------------


class TestAnalyzeHistory:
    """Integration tests for analyze_history."""

    def test_invalid_path(self) -> None:
        report = analyze_history("/nonexistent/path")
        assert len(report.errors) > 0

    def test_no_dependencies(self, tmp_path) -> None:
        report = analyze_history(str(tmp_path))
        assert len(report.errors) > 0 or report.package_count == 0


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


class TestRenderHistoryTable:
    """Tests for render_history_table."""

    def test_renders_without_error(self) -> None:
        from rich.console import Console

        report = HistoryReport(
            project_path="/tmp/test",
            packages=[
                PackageHistory(
                    name="a",
                    installed_version="1.0",
                    maintenance_trend=MaintenanceTrend.STEADY,
                    current_version_age_days=100,
                    releases_per_year=4.0,
                    avg_days_between_releases=90.0,
                    years_active=2.5,
                ),
            ],
        )
        console = Console(file=StringIO(), width=160)
        render_history_table(report, console=console)

    def test_renders_empty(self) -> None:
        from rich.console import Console

        report = HistoryReport(project_path="/tmp")
        console = Console(file=StringIO(), width=160)
        render_history_table(report, console=console)


class TestRenderHistoryJson:
    """Tests for render_history_json."""

    def test_produces_valid_json(self) -> None:
        from rich.console import Console

        report = HistoryReport(
            project_path="/tmp/test",
            packages=[
                PackageHistory(
                    name="a",
                    installed_version="1.0",
                    maintenance_trend=MaintenanceTrend.STEADY,
                    current_version_age_days=100,
                ),
            ],
        )
        buf = StringIO()
        console = Console(file=buf, width=1000, force_terminal=False, no_color=True)
        render_history_json(report, console=console)
        data = json.loads(buf.getvalue())
        assert "summary" in data
        assert "packages" in data
