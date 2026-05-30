"""Tests for the predict module — version prediction and deprecation risk analysis."""

from __future__ import annotations

import datetime
import json
from unittest.mock import MagicMock, patch

import pytest

from depcheck.models import HealthStatus, ParsedDependency
from depcheck.predict import (
    DeprecationRiskLevel,
    DeprecationSignals,
    PackagePrediction,
    PredictResult,
    ReleaseCadence,
    ReleaseInfo,
    ReleasePattern,
    VersionPrediction,
    _classify_cadence,
    _parse_release_date,
    analyze_package_prediction,
    analyze_release_pattern,
    calculate_deprecation_risk,
    detect_deprecation_signals,
    predict_next_version,
    render_predict_json,
    render_predict_table,
    run_predict,
)


# ---------------------------------------------------------------------------
# Unit tests for _parse_release_date
# ---------------------------------------------------------------------------


class TestParseReleaseDate:
    """Tests for _parse_release_date."""

    def test_iso8601_with_z(self) -> None:
        dt = _parse_release_date("2024-01-15T10:30:00Z")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 1
        assert dt.day == 15

    def test_iso8601_with_timezone(self) -> None:
        dt = _parse_release_date("2024-06-01T12:00:00+05:00")
        assert dt is not None
        assert dt.year == 2024
        assert dt.month == 6

    def test_empty_string(self) -> None:
        assert _parse_release_date("") is None

    def test_none_input(self) -> None:
        assert _parse_release_date(None) is None  # type: ignore

    def test_invalid_string(self) -> None:
        assert _parse_release_date("not-a-date") is None

    def test_date_only(self) -> None:
        dt = _parse_release_date("2024-01-15")
        assert dt is not None
        assert dt.year == 2024


# ---------------------------------------------------------------------------
# Unit tests for _classify_cadence
# ---------------------------------------------------------------------------


class TestClassifyCadence:
    """Tests for _classify_cadence."""

    def test_very_frequent(self) -> None:
        assert _classify_cadence(5) == ReleaseCadence.VERY_FREQUENT

    def test_frequent(self) -> None:
        assert _classify_cadence(20) == ReleaseCadence.FREQUENT

    def test_regular(self) -> None:
        assert _classify_cadence(60) == ReleaseCadence.REGULAR

    def test_infrequent(self) -> None:
        assert _classify_cadence(120) == ReleaseCadence.INFREQUENT

    def test_rare(self) -> None:
        assert _classify_cadence(250) == ReleaseCadence.RARE

    def test_stalled(self) -> None:
        assert _classify_cadence(400) == ReleaseCadence.STALLED

    def test_none(self) -> None:
        assert _classify_cadence(None) == ReleaseCadence.STALLED

    def test_boundary_values(self) -> None:
        assert _classify_cadence(13.9) == ReleaseCadence.VERY_FREQUENT
        assert _classify_cadence(14) == ReleaseCadence.FREQUENT
        assert _classify_cadence(29.9) == ReleaseCadence.FREQUENT
        assert _classify_cadence(30) == ReleaseCadence.REGULAR
        assert _classify_cadence(89.9) == ReleaseCadence.REGULAR
        assert _classify_cadence(90) == ReleaseCadence.INFREQUENT


# ---------------------------------------------------------------------------
# Unit tests for analyze_release_pattern
# ---------------------------------------------------------------------------


class TestAnalyzeReleasePattern:
    """Tests for analyze_release_pattern."""

    def test_none_info(self) -> None:
        pattern = analyze_release_pattern("test-pkg", None)
        assert pattern.package_name == "test-pkg"
        assert pattern.total_releases == 0
        assert pattern.stable_releases == 0

    def test_empty_releases(self) -> None:
        info = {"releases": {}}
        pattern = analyze_release_pattern("test-pkg", info)
        assert pattern.total_releases == 0

    def test_single_release(self) -> None:
        info = {
            "releases": {
                "1.0.0": [
                    {
                        "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                        "yanked": False,
                    }
                ]
            }
        }
        pattern = analyze_release_pattern("test-pkg", info)
        assert pattern.total_releases == 1
        assert pattern.stable_releases == 1
        assert pattern.first_release is not None
        assert pattern.latest_release is not None
        assert pattern.avg_days_between_releases is None  # Need 2+ for avg

    def test_multiple_releases(self) -> None:
        info = {
            "releases": {
                "1.0.0": [
                    {
                        "upload_time_iso_8601": "2023-01-15T10:00:00Z",
                        "yanked": False,
                    }
                ],
                "1.1.0": [
                    {
                        "upload_time_iso_8601": "2023-02-15T10:00:00Z",
                        "yanked": False,
                    }
                ],
                "1.2.0": [
                    {
                        "upload_time_iso_8601": "2023-03-15T10:00:00Z",
                        "yanked": False,
                    }
                ],
            }
        }
        pattern = analyze_release_pattern("test-pkg", info)
        assert pattern.total_releases == 3
        assert pattern.stable_releases == 3
        assert pattern.avg_days_between_releases is not None
        assert pattern.avg_days_between_releases > 0
        assert pattern.median_days_between_releases is not None
        assert pattern.releases_last_30d == 0  # These are from 2023

    def test_prerelease_detection(self) -> None:
        info = {
            "releases": {
                "1.0.0": [
                    {
                        "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                        "yanked": False,
                    }
                ],
                "1.1.0a1": [
                    {
                        "upload_time_iso_8601": "2024-02-15T10:00:00Z",
                        "yanked": False,
                    }
                ],
                "1.1.0b2": [
                    {
                        "upload_time_iso_8601": "2024-02-20T10:00:00Z",
                        "yanked": False,
                    }
                ],
            }
        }
        pattern = analyze_release_pattern("test-pkg", info)
        assert pattern.total_releases == 3
        assert pattern.stable_releases == 1
        assert pattern.prerelease_count == 2

    def test_yanked_detection(self) -> None:
        info = {
            "releases": {
                "1.0.0": [
                    {
                        "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                        "yanked": True,
                    }
                ],
                "1.1.0": [
                    {
                        "upload_time_iso_8601": "2024-02-15T10:00:00Z",
                        "yanked": False,
                    }
                ],
            }
        }
        pattern = analyze_release_pattern("test-pkg", info)
        assert pattern.yanked_count == 1

    def test_days_since_last_release(self) -> None:
        info = {
            "releases": {
                "1.0.0": [
                    {
                        "upload_time_iso_8601": "2024-06-01T10:00:00Z",
                        "yanked": False,
                    }
                ]
            }
        }
        pattern = analyze_release_pattern("test-pkg", info)
        assert pattern.days_since_last_release is not None
        assert pattern.days_since_last_release > 0

    def test_recent_releases_counting(self) -> None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        recent = (now - datetime.timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%SZ")
        last_60 = (now - datetime.timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
        last_200 = (now - datetime.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")

        info = {
            "releases": {
                "1.0.0": [{"upload_time_iso_8601": last_200, "yanked": False}],
                "1.1.0": [{"upload_time_iso_8601": last_60, "yanked": False}],
                "1.2.0": [{"upload_time_iso_8601": recent, "yanked": False}],
            }
        }
        pattern = analyze_release_pattern("test-pkg", info)
        assert pattern.releases_last_30d == 1
        assert pattern.releases_last_90d == 2
        assert pattern.releases_last_365d == 3


# ---------------------------------------------------------------------------
# Unit tests for predict_next_version
# ---------------------------------------------------------------------------


class TestPredictNextVersion:
    """Tests for predict_next_version."""

    def test_semver_prediction(self) -> None:
        pattern = ReleasePattern(
            package_name="test",
            stable_releases=10,
            median_days_between_releases=30.0,
            std_dev_days=5.0,
            releases_last_90d=3,
            releases_last_30d=1,
        )
        pred = predict_next_version("test", "1.2.3", {}, pattern)
        assert pred.predicted_next_major == "2.0.0"
        assert pred.predicted_next_minor == "1.3.0"
        assert pred.predicted_next_patch == "1.2.4"
        assert pred.estimated_days_to_next == 30.0

    def test_two_part_version(self) -> None:
        pattern = ReleasePattern(package_name="test", stable_releases=5)
        pred = predict_next_version("test", "2.5", {}, pattern)
        assert pred.predicted_next_major == "3.0"
        assert pred.predicted_next_minor == "2.6"

    def test_single_part_version(self) -> None:
        pattern = ReleasePattern(package_name="test", stable_releases=3)
        pred = predict_next_version("test", "3", {}, pattern)
        assert pred.predicted_next_major == "4"
        assert pred.predicted_next_minor == "3.1"

    def test_no_current_version(self) -> None:
        pattern = ReleasePattern(package_name="test")
        pred = predict_next_version("test", None, {}, pattern)
        assert pred.basis == "no_current_version"
        assert pred.predicted_next_major is None

    def test_unparseable_version(self) -> None:
        pattern = ReleasePattern(package_name="test")
        pred = predict_next_version("test", "not-a-version", {}, pattern)
        assert pred.basis == "unparseable_version"

    def test_confidence_with_high_data(self) -> None:
        pattern = ReleasePattern(
            package_name="test",
            stable_releases=25,
            median_days_between_releases=30.0,
            avg_days_between_releases=30.0,
            std_dev_days=5.0,
            releases_last_90d=5,
            releases_last_30d=1,
        )
        pred = predict_next_version("test", "1.0.0", {}, pattern)
        assert pred.confidence >= 0.5

    def test_confidence_with_low_data(self) -> None:
        pattern = ReleasePattern(
            package_name="test",
            stable_releases=1,
            median_days_between_releases=None,
        )
        pred = predict_next_version("test", "1.0.0", {}, pattern)
        assert pred.confidence < 0.3


# ---------------------------------------------------------------------------
# Unit tests for detect_deprecation_signals
# ---------------------------------------------------------------------------


class TestDetectDeprecationSignals:
    """Tests for detect_deprecation_signals."""

    def test_no_signals_healthy_package(self) -> None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        pattern = ReleasePattern(
            package_name="test",
            total_releases=20,
            stable_releases=18,
            days_since_last_release=30,
            releases_last_365d=8,
            release_history=[
                ReleaseInfo(version="1.0.0", date=now - datetime.timedelta(days=365 * 2)),
                ReleaseInfo(version="1.1.0", date=now - datetime.timedelta(days=365)),
                ReleaseInfo(version="1.2.0", date=now - datetime.timedelta(days=30)),
            ],
        )
        signals = detect_deprecation_signals("test", pattern, {"releases": {}})
        assert signals.signal_count == 0
        assert not signals.no_releases_over_365d

    def test_signal_no_releases_over_365d(self) -> None:
        pattern = ReleasePattern(
            package_name="test",
            days_since_last_release=400,
        )
        signals = detect_deprecation_signals("test", pattern, {"releases": {}})
        assert signals.no_releases_over_365d
        assert signals.signal_count >= 1

    def test_signal_removed_from_pypi(self) -> None:
        pattern = ReleasePattern(package_name="test")
        signals = detect_deprecation_signals("test", pattern, None)
        assert signals.removed_from_pypi
        assert signals.signal_count >= 1

    def test_signal_high_vulnerability_count(self) -> None:
        pattern = ReleasePattern(package_name="test")
        signals = detect_deprecation_signals("test", pattern, {"releases": {}}, vulnerabilities_count=5)
        assert signals.high_vulnerability_count
        assert signals.signal_count >= 1

    def test_signal_no_maintainer_response(self) -> None:
        pattern = ReleasePattern(
            package_name="test",
            days_since_last_release=800,
            stable_releases=5,
        )
        signals = detect_deprecation_signals("test", pattern, {"releases": {}})
        assert signals.no_maintainer_response
        assert signals.no_releases_over_365d

    def test_signal_yanked_recent_releases(self) -> None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        pattern = ReleasePattern(
            package_name="test",
            release_history=[
                ReleaseInfo(version="1.0.0", date=now - datetime.timedelta(days=100), is_yanked=True),
                ReleaseInfo(version="1.1.0", date=now - datetime.timedelta(days=80), is_yanked=True),
                ReleaseInfo(version="1.2.0", date=now - datetime.timedelta(days=60)),
                ReleaseInfo(version="1.3.0", date=now - datetime.timedelta(days=40), is_yanked=True),
                ReleaseInfo(version="1.4.0", date=now - datetime.timedelta(days=20)),
                ReleaseInfo(version="1.5.0", date=now - datetime.timedelta(days=10), is_yanked=True),
            ],
        )
        signals = detect_deprecation_signals("test", pattern, {"releases": {}})
        assert signals.yanked_recent_releases

    def test_signal_declining_frequency(self) -> None:
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        pattern = ReleasePattern(
            package_name="test",
            total_releases=20,
            stable_releases=15,
            first_release=now - datetime.timedelta(days=730),
            latest_release=now - datetime.timedelta(days=10),
            releases_last_365d=1,  # Very low recent activity
        )
        signals = detect_deprecation_signals("test", pattern, {"releases": {}})
        assert signals.declining_release_frequency


# ---------------------------------------------------------------------------
# Unit tests for calculate_deprecation_risk
# ---------------------------------------------------------------------------


class TestCalculateDeprecationRisk:
    """Tests for calculate_deprecation_risk."""

    def test_low_risk(self) -> None:
        signals = DeprecationSignals(package_name="test")
        level, score = calculate_deprecation_risk(signals)
        assert level == DeprecationRiskLevel.LOW
        assert score == 0

    def test_moderate_risk(self) -> None:
        signals = DeprecationSignals(
            package_name="test",
            no_releases_over_365d=True,
        )
        level, score = calculate_deprecation_risk(signals)
        assert level == DeprecationRiskLevel.MODERATE
        assert score == 15

    def test_high_risk(self) -> None:
        signals = DeprecationSignals(
            package_name="test",
            no_releases_over_365d=True,
            declining_release_frequency=True,
            high_vulnerability_count=True,
        )
        level, score = calculate_deprecation_risk(signals)
        assert level == DeprecationRiskLevel.HIGH
        assert score == 30

    def test_critical_risk(self) -> None:
        signals = DeprecationSignals(
            package_name="test",
            removed_from_pypi=True,
            no_releases_over_365d=True,
        )
        level, score = calculate_deprecation_risk(signals)
        assert level == DeprecationRiskLevel.CRITICAL
        assert score == 55  # 40 (removed) + 15 (no_releases)

    def test_combined_signals(self) -> None:
        signals = DeprecationSignals(
            package_name="test",
            removed_from_pypi=True,
            no_maintainer_response=True,
            no_releases_over_365d=True,
            high_vulnerability_count=True,
        )
        level, score = calculate_deprecation_risk(signals)
        assert level == DeprecationRiskLevel.CRITICAL
        assert score > 40


# ---------------------------------------------------------------------------
# Unit tests for PredictResult and PackagePrediction serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    """Tests for to_dict serialization."""

    def test_release_info_to_dict(self) -> None:
        ri = ReleaseInfo(
            version="1.0.0",
            date=datetime.datetime(2024, 1, 15, tzinfo=datetime.timezone.utc),
        )
        d = ri.to_dict()
        assert d["version"] == "1.0.0"
        assert "2024-01-15" in d["date"]

    def test_release_pattern_to_dict(self) -> None:
        rp = ReleasePattern(
            package_name="test",
            total_releases=10,
            stable_releases=8,
            cadence=ReleaseCadence.REGULAR,
        )
        d = rp.to_dict()
        assert d["package_name"] == "test"
        assert d["total_releases"] == 10
        assert d["cadence"] == "regular"

    def test_version_prediction_to_dict(self) -> None:
        vp = VersionPrediction(
            package_name="test",
            current_version="1.0.0",
            predicted_next_minor="1.1.0",
            confidence=0.75,
        )
        d = vp.to_dict()
        assert d["predicted_next_minor"] == "1.1.0"
        assert d["confidence"] == 0.75

    def test_deprecation_signals_to_dict(self) -> None:
        ds = DeprecationSignals(
            package_name="test",
            no_releases_over_365d=True,
            signal_count=1,
            signal_details=["No releases in 400 days"],
        )
        d = ds.to_dict()
        assert d["no_releases_over_365d"] is True
        assert len(d["signal_details"]) == 1

    def test_package_prediction_to_dict(self) -> None:
        pp = PackagePrediction(
            package_name="test",
            installed_version="1.0.0",
            health_status=HealthStatus.HEALTHY,
            deprecation_risk=DeprecationRiskLevel.LOW,
            deprecation_risk_score=5.0,
        )
        d = pp.to_dict()
        assert d["package_name"] == "test"
        assert d["health_status"] == "healthy"
        assert d["deprecation_risk"] == "low"

    def test_predict_result_to_dict(self) -> None:
        pr = PredictResult(
            project_path="/test",
            total_packages=5,
            low_risk_count=3,
            moderate_risk_count=1,
            high_risk_count=1,
            critical_risk_count=0,
            overall_deprecation_risk=DeprecationRiskLevel.HIGH,
        )
        d = pr.to_dict()
        assert d["total_packages"] == 5
        assert d["risk_summary"]["high"] == 1
        assert d["overall_deprecation_risk"] == "high"

    def test_json_roundtrip(self) -> None:
        pr = PredictResult(
            project_path="/test",
            total_packages=2,
            overall_deprecation_risk=DeprecationRiskLevel.LOW,
            packages=[
                PackagePrediction(
                    package_name="pkg-a",
                    installed_version="1.0.0",
                    health_status=HealthStatus.HEALTHY,
                ),
                PackagePrediction(
                    package_name="pkg-b",
                    installed_version="2.0.0",
                    health_status=HealthStatus.OUTDATED,
                    deprecation_risk=DeprecationRiskLevel.MODERATE,
                    deprecation_risk_score=15.0,
                ),
            ],
        )
        data = json.dumps(pr.to_dict())
        parsed = json.loads(data)
        assert parsed["total_packages"] == 2
        assert len(parsed["packages"]) == 2


# ---------------------------------------------------------------------------
# Unit tests for analyze_package_prediction with mocks
# ---------------------------------------------------------------------------


class TestAnalyzePackagePrediction:
    """Tests for analyze_package_prediction with mocked API clients."""

    def _make_mock_info(self) -> dict:
        """Create a mock PyPI info dict."""
        return {
            "info": {
                "version": "2.0.0",
                "classifiers": [],
                "requires_dist": [],
            },
            "releases": {
                "1.0.0": [
                    {
                        "upload_time_iso_8601": "2023-01-15T10:00:00Z",
                        "yanked": False,
                        "filename": "test-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "size": 50000,
                    }
                ],
                "2.0.0": [
                    {
                        "upload_time_iso_8601": "2024-06-01T10:00:00Z",
                        "yanked": False,
                        "filename": "test-2.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "size": 55000,
                    }
                ],
            },
        }

    def test_basic_analysis(self) -> None:
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = self._make_mock_info()
        mock_pypi.resolve_version.return_value = "2.0.0"

        mock_osv = MagicMock()
        mock_osv.query_vulnerabilities.return_value = []

        dep = ParsedDependency(name="test-pkg", version="2.0.0")
        pred = analyze_package_prediction(dep, mock_pypi, mock_osv, check_vulnerabilities=False)

        assert pred.package_name == "test-pkg"
        assert pred.installed_version == "2.0.0"
        assert pred.release_pattern is not None
        assert pred.version_prediction is not None
        assert pred.deprecation_signals is not None

    def test_package_not_found(self) -> None:
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = None

        mock_osv = MagicMock()

        dep = ParsedDependency(name="nonexistent", version="1.0.0")
        pred = analyze_package_prediction(dep, mock_pypi, mock_osv, check_vulnerabilities=False)

        assert pred.health_status == HealthStatus.REMOVED
        assert pred.error is not None
        assert pred.deprecation_signals is not None
        assert pred.deprecation_signals.removed_from_pypi


# ---------------------------------------------------------------------------
# Unit tests for rendering
# ---------------------------------------------------------------------------


class TestRendering:
    """Tests for render functions."""

    def test_render_predict_table(self, capsys: pytest.CaptureFixture) -> None:
        result = PredictResult(
            project_path="/test",
            total_packages=2,
            low_risk_count=1,
            moderate_risk_count=1,
            high_risk_count=0,
            critical_risk_count=0,
            overall_deprecation_risk=DeprecationRiskLevel.MODERATE,
            packages=[
                PackagePrediction(
                    package_name="pkg-a",
                    installed_version="1.0.0",
                    health_status=HealthStatus.HEALTHY,
                    deprecation_risk=DeprecationRiskLevel.LOW,
                    deprecation_risk_score=0.0,
                ),
                PackagePrediction(
                    package_name="pkg-b",
                    installed_version="2.0.0",
                    health_status=HealthStatus.OUTDATED,
                    deprecation_risk=DeprecationRiskLevel.MODERATE,
                    deprecation_risk_score=15.0,
                    deprecation_signals=DeprecationSignals(
                        package_name="pkg-b",
                        no_releases_over_365d=True,
                        signal_count=1,
                        signal_details=["No releases in 400 days"],
                    ),
                ),
            ],
        )
        # Just verify it doesn't crash
        render_predict_table(result)

    def test_render_predict_json(self) -> None:
        result = PredictResult(
            project_path="/test",
            total_packages=1,
            overall_deprecation_risk=DeprecationRiskLevel.LOW,
            packages=[
                PackagePrediction(
                    package_name="pkg-a",
                    installed_version="1.0.0",
                    health_status=HealthStatus.HEALTHY,
                ),
            ],
        )
        from io import StringIO

        from rich.console import Console

        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_predict_json(result, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert data["total_packages"] == 1
