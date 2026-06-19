"""Version prediction and deprecation risk analysis for depcheck.

Analyzes package release history to predict next version numbers,
estimate release cadence, detect deprecation signals, and calculate
a comprehensive deprecation risk score for each dependency.
"""

from __future__ import annotations

import datetime
import enum
import json
import statistics
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.version import Version
from rich.console import Console
from rich.table import Table

from depcheck.models import HealthStatus, ParsedDependency
from depcheck.osv import OSVClient
from depcheck.pypi import PyPIClient
from depcheck.scanner import (
    check_package_health,
    discover_dependencies,
)


class DeprecationRiskLevel(enum.Enum):
    """Risk level for package deprecation."""

    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"
    CRITICAL = "critical"


class ReleaseCadence(enum.Enum):
    """Classification of package release cadence."""

    VERY_FREQUENT = "very_frequent"  # < 14 days between releases
    FREQUENT = "frequent"  # 14-30 days
    REGULAR = "regular"  # 30-90 days
    INFREQUENT = "infrequent"  # 90-180 days
    RARE = "rare"  # 180-365 days
    STALLED = "stalled"  # > 365 days


@dataclass
class ReleaseInfo:
    """Information about a single release."""

    version: str
    date: datetime.datetime
    is_prerelease: bool = False
    is_yanked: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "date": self.date.isoformat(),
            "is_prerelease": self.is_prerelease,
            "is_yanked": self.is_yanked,
        }


@dataclass
class ReleasePattern:
    """Analyzed release pattern for a package."""

    package_name: str
    total_releases: int = 0
    stable_releases: int = 0
    prerelease_count: int = 0
    yanked_count: int = 0
    first_release: datetime.datetime | None = None
    latest_release: datetime.datetime | None = None
    avg_days_between_releases: float | None = None
    median_days_between_releases: float | None = None
    std_dev_days: float | None = None
    cadence: ReleaseCadence = ReleaseCadence.REGULAR
    releases_last_30d: int = 0
    releases_last_90d: int = 0
    releases_last_365d: int = 0
    days_since_last_release: int | None = None
    release_history: list[ReleaseInfo] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "total_releases": self.total_releases,
            "stable_releases": self.stable_releases,
            "prerelease_count": self.prerelease_count,
            "yanked_count": self.yanked_count,
            "first_release": self.first_release.isoformat() if self.first_release else None,
            "latest_release": self.latest_release.isoformat() if self.latest_release else None,
            "avg_days_between_releases": round(self.avg_days_between_releases, 1)
            if self.avg_days_between_releases
            else None,
            "median_days_between_releases": round(self.median_days_between_releases, 1)
            if self.median_days_between_releases
            else None,
            "std_dev_days": round(self.std_dev_days, 1) if self.std_dev_days else None,
            "cadence": self.cadence.value,
            "releases_last_30d": self.releases_last_30d,
            "releases_last_90d": self.releases_last_90d,
            "releases_last_365d": self.releases_last_365d,
            "days_since_last_release": self.days_since_last_release,
            "release_history": [r.to_dict() for r in self.release_history[-10:]],
        }


@dataclass
class VersionPrediction:
    """Predicted next version for a package."""

    package_name: str
    current_version: str | None = None
    predicted_next_major: str | None = None
    predicted_next_minor: str | None = None
    predicted_next_patch: str | None = None
    confidence: float = 0.0
    estimated_days_to_next: float | None = None
    basis: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "current_version": self.current_version,
            "predicted_next_major": self.predicted_next_major,
            "predicted_next_minor": self.predicted_next_minor,
            "predicted_next_patch": self.predicted_next_patch,
            "confidence": round(self.confidence, 3),
            "estimated_days_to_next": round(self.estimated_days_to_next, 1)
            if self.estimated_days_to_next
            else None,
            "basis": self.basis,
        }


@dataclass
class DeprecationSignals:
    """Signals that a package may be deprecated or abandoned."""

    package_name: str
    no_releases_over_365d: bool = False
    declining_release_frequency: bool = False
    increasing_gap_between_releases: bool = False
    yanked_recent_releases: bool = False
    no_maintainer_response: bool = False  # Heuristic based on age
    only_prerelease_releases: bool = False
    removed_from_pypi: bool = False
    high_vulnerability_count: bool = False
    signal_count: int = 0
    signal_details: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "no_releases_over_365d": self.no_releases_over_365d,
            "declining_release_frequency": self.declining_release_frequency,
            "increasing_gap_between_releases": self.increasing_gap_between_releases,
            "yanked_recent_releases": self.yanked_recent_releases,
            "no_maintainer_response": self.no_maintainer_response,
            "only_prerelease_releases": self.only_prerelease_releases,
            "removed_from_pypi": self.removed_from_pypi,
            "high_vulnerability_count": self.high_vulnerability_count,
            "signal_count": self.signal_count,
            "signal_details": self.signal_details,
        }


@dataclass
class PackagePrediction:
    """Complete prediction analysis for a single package."""

    package_name: str
    installed_version: str | None = None
    health_status: HealthStatus = HealthStatus.UNKNOWN
    release_pattern: ReleasePattern | None = None
    version_prediction: VersionPrediction | None = None
    deprecation_signals: DeprecationSignals | None = None
    deprecation_risk: DeprecationRiskLevel = DeprecationRiskLevel.LOW
    deprecation_risk_score: float = 0.0
    vulnerabilities_count: int = 0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "health_status": self.health_status.value,
            "release_pattern": self.release_pattern.to_dict() if self.release_pattern else None,
            "version_prediction": self.version_prediction.to_dict()
            if self.version_prediction
            else None,
            "deprecation_signals": self.deprecation_signals.to_dict()
            if self.deprecation_signals
            else None,
            "deprecation_risk": self.deprecation_risk.value,
            "deprecation_risk_score": round(self.deprecation_risk_score, 2),
            "vulnerabilities_count": self.vulnerabilities_count,
            "error": self.error,
        }


@dataclass
class PredictResult:
    """Result of a full predict analysis for a project."""

    project_path: str = ""
    packages: list[PackagePrediction] = field(default_factory=list)
    total_packages: int = 0
    low_risk_count: int = 0
    moderate_risk_count: int = 0
    high_risk_count: int = 0
    critical_risk_count: int = 0
    overall_deprecation_risk: DeprecationRiskLevel = DeprecationRiskLevel.LOW
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "total_packages": self.total_packages,
            "risk_summary": {
                "low": self.low_risk_count,
                "moderate": self.moderate_risk_count,
                "high": self.high_risk_count,
                "critical": self.critical_risk_count,
            },
            "overall_deprecation_risk": self.overall_deprecation_risk.value,
            "packages": [p.to_dict() for p in self.packages],
            "errors": self.errors,
        }


def _parse_release_date(date_str: str) -> datetime.datetime | None:
    """Parse an ISO 8601 date string into a datetime object.

    Args:
        date_str: ISO 8601 date string (e.g., '2024-01-15T10:30:00Z').

    Returns:
        Parsed datetime, or None if parsing fails.
    """
    if not date_str:
        return None
    try:
        return datetime.datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _classify_cadence(avg_days: float | None) -> ReleaseCadence:
    """Classify release cadence based on average days between releases.

    Args:
        avg_days: Average days between releases.

    Returns:
        The ReleaseCadence classification.
    """
    if avg_days is None:
        return ReleaseCadence.STALLED
    if avg_days < 14:
        return ReleaseCadence.VERY_FREQUENT
    if avg_days < 30:
        return ReleaseCadence.FREQUENT
    if avg_days < 90:
        return ReleaseCadence.REGULAR
    if avg_days < 180:
        return ReleaseCadence.INFREQUENT
    if avg_days < 365:
        return ReleaseCadence.RARE
    return ReleaseCadence.STALLED


def analyze_release_pattern(
    package_name: str,
    pypi_info: dict[str, Any] | None,
) -> ReleasePattern:
    """Analyze the release pattern of a package from PyPI data.

    Args:
        package_name: Normalized package name.
        pypi_info: PyPI package info dictionary (or None if not found).

    Returns:
        ReleasePattern with analysis results.
    """
    pattern = ReleasePattern(package_name=package_name)

    if pypi_info is None:
        return pattern

    releases_data = pypi_info.get("releases", {})
    now = datetime.datetime.now(tz=datetime.UTC)

    stable_releases: list[ReleaseInfo] = []
    all_releases: list[ReleaseInfo] = []

    for ver_str, files in releases_data.items():
        if not files:
            continue

        is_yanked = all(f.get("yanked", False) for f in files)
        is_prerelease = False

        try:
            ver = Version(ver_str)
            is_prerelease = ver.is_prerelease or ver.is_devrelease
        except Exception:
            # Can't parse version, treat as non-prerelease
            pass

        # Get the upload date from the first file
        upload_time = None
        for f in files:
            raw_date = f.get("upload_time_iso_8601")
            if raw_date:
                upload_time = _parse_release_date(raw_date)
                break

        if upload_time is None:
            continue

        release = ReleaseInfo(
            version=ver_str,
            date=upload_time,
            is_prerelease=is_prerelease,
            is_yanked=is_yanked,
        )
        all_releases.append(release)

        if not is_prerelease:
            stable_releases.append(release)
            if is_yanked:
                pattern.yanked_count += 1

    # Sort by date
    all_releases.sort(key=lambda r: r.date)
    stable_releases.sort(key=lambda r: r.date)

    pattern.total_releases = len(all_releases)
    pattern.stable_releases = len(stable_releases)
    pattern.prerelease_count = len(all_releases) - len(stable_releases)
    pattern.release_history = all_releases

    if not all_releases:
        return pattern

    pattern.first_release = all_releases[0].date
    pattern.latest_release = all_releases[-1].date

    if pattern.latest_release:
        pattern.days_since_last_release = (now - pattern.latest_release).days

    # Calculate inter-release intervals using stable releases
    if len(stable_releases) >= 2:
        intervals: list[float] = []
        for i in range(1, len(stable_releases)):
            delta = (stable_releases[i].date - stable_releases[i - 1].date).total_seconds()
            days = delta / 86400.0
            if days >= 0:
                intervals.append(days)

        if intervals:
            pattern.avg_days_between_releases = statistics.mean(intervals)
            pattern.median_days_between_releases = statistics.median(intervals)
            if len(intervals) >= 2:
                pattern.std_dev_days = statistics.stdev(intervals)
            else:
                pattern.std_dev_days = 0.0

    # Classify cadence
    pattern.cadence = _classify_cadence(pattern.median_days_between_releases)

    # Count releases in time windows
    for release in stable_releases:
        days_ago = (now - release.date).days
        if days_ago <= 30:
            pattern.releases_last_30d += 1
        if days_ago <= 90:
            pattern.releases_last_90d += 1
        if days_ago <= 365:
            pattern.releases_last_365d += 1

    return pattern


def predict_next_version(
    package_name: str,
    current_version: str | None,
    pypi_info: dict[str, Any] | None,
    release_pattern: ReleasePattern,
) -> VersionPrediction:
    """Predict the next version number for a package.

    Uses the release history and semantic versioning patterns to predict
    likely next version numbers for major, minor, and patch releases.

    Args:
        package_name: Package name.
        current_version: Current installed version.
        pypi_info: PyPI package info.
        release_pattern: Analyzed release pattern.

    Returns:
        VersionPrediction with predicted versions.
    """
    prediction = VersionPrediction(package_name=package_name, current_version=current_version)

    if current_version is None:
        prediction.basis = "no_current_version"
        return prediction

    try:
        current = Version(current_version)
    except Exception:
        prediction.basis = "unparseable_version"
        return prediction

    # Predict based on semver
    if current.release and len(current.release) >= 3:
        major, minor, patch = current.release[0], current.release[1], current.release[2]
        prediction.predicted_next_major = f"{major + 1}.0.0"
        prediction.predicted_next_minor = f"{major}.{minor + 1}.0"
        prediction.predicted_next_patch = f"{major}.{minor}.{patch + 1}"
    elif current.release and len(current.release) == 2:
        major, minor = current.release[0], current.release[1]
        prediction.predicted_next_major = f"{major + 1}.0"
        prediction.predicted_next_minor = f"{major}.{minor + 1}"
        prediction.predicted_next_patch = f"{major}.{minor}.1"
    elif current.release and len(current.release) == 1:
        major = current.release[0]
        prediction.predicted_next_major = f"{major + 1}"
        prediction.predicted_next_minor = f"{major}.1"
        prediction.predicted_next_patch = f"{major}.0.1"
    else:
        prediction.basis = "non_standard_version"
        return prediction

    # Estimate time to next release based on cadence
    if (
        release_pattern.median_days_between_releases
        and release_pattern.median_days_between_releases > 0
    ):
        prediction.estimated_days_to_next = release_pattern.median_days_between_releases

    # Confidence based on number of stable releases and regularity
    confidence = 0.0
    if release_pattern.stable_releases >= 20:
        confidence += 0.3
    elif release_pattern.stable_releases >= 10:
        confidence += 0.2
    elif release_pattern.stable_releases >= 3:
        confidence += 0.1

    if release_pattern.std_dev_days is not None and release_pattern.avg_days_between_releases:
        if release_pattern.avg_days_between_releases > 0:
            cv = release_pattern.std_dev_days / release_pattern.avg_days_between_releases
            if cv < 0.3:
                confidence += 0.3
            elif cv < 0.6:
                confidence += 0.2
            elif cv < 1.0:
                confidence += 0.1

    # Recent activity boosts confidence
    if release_pattern.releases_last_90d > 0:
        confidence += 0.2
    if release_pattern.releases_last_30d > 0:
        confidence += 0.2

    prediction.confidence = min(confidence, 1.0)
    prediction.basis = "semver_pattern" if confidence > 0.3 else "low_data"

    return prediction


def detect_deprecation_signals(
    package_name: str,
    release_pattern: ReleasePattern,
    pypi_info: dict[str, Any] | None,
    vulnerabilities_count: int = 0,
) -> DeprecationSignals:
    """Detect signals that a package may be deprecated or abandoned.

    Args:
        package_name: Package name.
        release_pattern: Analyzed release pattern.
        pypi_info: PyPI package info.
        vulnerabilities_count: Number of known vulnerabilities.

    Returns:
        DeprecationSignals with detected signals.
    """
    signals = DeprecationSignals(package_name=package_name)
    details: list[str] = []

    # Signal: No releases for over 365 days
    if (
        release_pattern.days_since_last_release is not None
        and release_pattern.days_since_last_release > 365
    ):
        signals.no_releases_over_365d = True
        details.append(
            f"No releases in {release_pattern.days_since_last_release} days (>365 threshold)"
        )

    # Signal: Declining release frequency
    # Compare recent activity (last 365 days) vs. historical
    if (
        release_pattern.releases_last_365d is not None
        and release_pattern.total_releases > 5
        and release_pattern.first_release is not None
        and release_pattern.latest_release is not None
    ):
        total_span_days = (release_pattern.latest_release - release_pattern.first_release).days
        if total_span_days > 0:
            historical_rate = release_pattern.stable_releases / (total_span_days / 365.0)
            if release_pattern.releases_last_365d < historical_rate * 0.3 and historical_rate > 2:
                signals.declining_release_frequency = True
                details.append(
                    f"Release frequency declined: {release_pattern.releases_last_365d} in last "
                    f"year vs {historical_rate:.1f}/yr historical average"
                )

    # Signal: Increasing gap between releases
    if release_pattern.release_history and len(release_pattern.release_history) >= 6:
        stable = [r for r in release_pattern.release_history if not r.is_prerelease]
        if len(stable) >= 6:
            # Compare gaps in first half vs second half
            mid = len(stable) // 2
            first_half_gaps: list[float] = []
            second_half_gaps: list[float] = []
            for i in range(1, mid):
                gap = (stable[i].date - stable[i - 1].date).total_seconds() / 86400.0
                first_half_gaps.append(gap)
            for i in range(mid + 1, len(stable)):
                gap = (stable[i].date - stable[i - 1].date).total_seconds() / 86400.0
                second_half_gaps.append(gap)

            if first_half_gaps and second_half_gaps:
                avg_first = statistics.mean(first_half_gaps)
                avg_second = statistics.mean(second_half_gaps)
                if avg_second > avg_first * 2 and avg_first > 0:
                    signals.increasing_gap_between_releases = True
                    details.append(
                        f"Release gaps increasing: recent avg {avg_second:.0f}d vs "
                        f"earlier avg {avg_first:.0f}d"
                    )

    # Signal: Yanked recent releases
    if release_pattern.release_history:
        recent = [r for r in release_pattern.release_history if not r.is_prerelease][-5:]
        yanked_recent = sum(1 for r in recent if r.is_yanked)
        if yanked_recent >= 2:
            signals.yanked_recent_releases = True
            details.append(f"{yanked_recent} of last 5 releases were yanked")

    # Signal: Package removed from PyPI
    if pypi_info is None:
        signals.removed_from_pypi = True
        details.append("Package not found on PyPI (may be removed)")

    # Signal: Only prerelease releases in recent history
    if release_pattern.release_history:
        last_10 = release_pattern.release_history[-10:]
        stable_recent = [r for r in last_10 if not r.is_prerelease and not r.is_yanked]
        prerelease_recent = [r for r in last_10 if r.is_prerelease]
        if len(prerelease_recent) > 0 and len(stable_recent) == 0 and len(last_10) >= 3:
            signals.only_prerelease_releases = True
            details.append("Only prerelease releases in recent history")

    # Signal: High vulnerability count
    if vulnerabilities_count >= 3:
        signals.high_vulnerability_count = True
        details.append(f"Has {vulnerabilities_count} known vulnerabilities")

    # Signal: Very old package with no recent activity (no maintainer response heuristic)
    if (
        release_pattern.days_since_last_release is not None
        and release_pattern.days_since_last_release > 730  # 2 years
        and release_pattern.stable_releases > 0
    ):
        signals.no_maintainer_response = True
        details.append(
            f"No maintainer activity in {release_pattern.days_since_last_release}"
            f" days (>730 threshold)"
        )

    signals.signal_count = sum(
        [
            signals.no_releases_over_365d,
            signals.declining_release_frequency,
            signals.increasing_gap_between_releases,
            signals.yanked_recent_releases,
            signals.no_maintainer_response,
            signals.only_prerelease_releases,
            signals.removed_from_pypi,
            signals.high_vulnerability_count,
        ]
    )
    signals.signal_details = details

    return signals


def calculate_deprecation_risk(signals: DeprecationSignals) -> tuple[DeprecationRiskLevel, float]:
    """Calculate a deprecation risk score and level from detected signals.

    Uses a weighted scoring system:
    - removed_from_pypi: 40 points (definitive signal)
    - no_maintainer_response: 25 points
    - no_releases_over_365d: 15 points
    - declining_release_frequency: 10 points
    - increasing_gap_between_releases: 10 points
    - yanked_recent_releases: 8 points
    - only_prerelease_releases: 7 points
    - high_vulnerability_count: 5 points

    Score thresholds:
    - 0-10: LOW
    - 11-25: MODERATE
    - 26-40: HIGH
    - 41+: CRITICAL

    Args:
        signals: The detected deprecation signals.

    Returns:
        Tuple of (risk level, numeric score).
    """
    score = 0.0

    if signals.removed_from_pypi:
        score += 40
    if signals.no_maintainer_response:
        score += 25
    if signals.no_releases_over_365d:
        score += 15
    if signals.declining_release_frequency:
        score += 10
    if signals.increasing_gap_between_releases:
        score += 10
    if signals.yanked_recent_releases:
        score += 8
    if signals.only_prerelease_releases:
        score += 7
    if signals.high_vulnerability_count:
        score += 5

    if score <= 10:
        level = DeprecationRiskLevel.LOW
    elif score <= 25:
        level = DeprecationRiskLevel.MODERATE
    elif score <= 40:
        level = DeprecationRiskLevel.HIGH
    else:
        level = DeprecationRiskLevel.CRITICAL

    return level, score


def analyze_package_prediction(
    dep: ParsedDependency,
    pypi_client: PyPIClient,
    osv_client: OSVClient,
    check_vulnerabilities: bool = True,
) -> PackagePrediction:
    """Run full prediction analysis on a single package.

    Args:
        dep: The parsed dependency.
        pypi_client: PyPI API client.
        osv_client: OSV API client.
        check_vulnerabilities: Whether to check for vulnerabilities.

    Returns:
        PackagePrediction with complete analysis.
    """
    pred = PackagePrediction(
        package_name=dep.name,
        installed_version=dep.version,
    )

    # Fetch PyPI info
    info = pypi_client.get_package_info(dep.name)

    if info is None:
        pred.health_status = HealthStatus.REMOVED
        pred.error = "Package not found on PyPI"
        # Still generate signals for removed packages
        signals = detect_deprecation_signals(dep.name, ReleasePattern(package_name=dep.name), None)
        signals.removed_from_pypi = True
        signals.signal_count = sum(
            [
                signals.no_releases_over_365d,
                signals.declining_release_frequency,
                signals.increasing_gap_between_releases,
                signals.yanked_recent_releases,
                signals.no_maintainer_response,
                signals.only_prerelease_releases,
                True,
                signals.high_vulnerability_count,
            ]
        )
        level, score = calculate_deprecation_risk(signals)
        pred.deprecation_signals = signals
        pred.deprecation_risk = level
        pred.deprecation_risk_score = score
        return pred

    # Resolve installed version
    resolved_version = pypi_client.resolve_version(dep, info)
    if resolved_version:
        pred.installed_version = resolved_version

    # Check health
    report = check_package_health(
        dep,
        pypi_client,
        osv_client,
        check_vulnerabilities=check_vulnerabilities,
    )
    pred.health_status = report.status
    pred.vulnerabilities_count = len(report.vulnerabilities)

    # Analyze release pattern
    release_pattern = analyze_release_pattern(dep.name, info)
    pred.release_pattern = release_pattern

    # Predict next version
    version_pred = predict_next_version(dep.name, pred.installed_version, info, release_pattern)
    pred.version_prediction = version_pred

    # Detect deprecation signals
    signals = detect_deprecation_signals(
        dep.name, release_pattern, info, pred.vulnerabilities_count
    )
    pred.deprecation_signals = signals

    # Calculate deprecation risk
    level, score = calculate_deprecation_risk(signals)
    pred.deprecation_risk = level
    pred.deprecation_risk_score = score

    return pred


def run_predict(
    project_path: str | Path,
    check_vulnerabilities: bool = True,
) -> PredictResult:
    """Run prediction analysis on all project dependencies.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to check for vulnerabilities.

    Returns:
        PredictResult with analysis for all dependencies.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return PredictResult(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    dependencies, _ = discover_dependencies(project_path)

    if not dependencies:
        return PredictResult(
            project_path=str(project_path),
            errors=["No dependencies found in the project."],
        )

    predictions: list[PackagePrediction] = []

    with PyPIClient() as pypi_client, OSVClient() as osv_client:
        for dep in dependencies:
            try:
                pred = analyze_package_prediction(
                    dep, pypi_client, osv_client, check_vulnerabilities
                )
                predictions.append(pred)
            except Exception as exc:
                predictions.append(
                    PackagePrediction(
                        package_name=dep.name,
                        installed_version=dep.version,
                        error=str(exc),
                    )
                )

    # Build result
    result = PredictResult(
        project_path=str(project_path),
        packages=predictions,
        total_packages=len(predictions),
    )

    # Count risk levels
    result.low_risk_count = sum(
        1 for p in predictions if p.deprecation_risk == DeprecationRiskLevel.LOW
    )
    result.moderate_risk_count = sum(
        1 for p in predictions if p.deprecation_risk == DeprecationRiskLevel.MODERATE
    )
    result.high_risk_count = sum(
        1 for p in predictions if p.deprecation_risk == DeprecationRiskLevel.HIGH
    )
    result.critical_risk_count = sum(
        1 for p in predictions if p.deprecation_risk == DeprecationRiskLevel.CRITICAL
    )

    # Determine overall risk (highest non-zero level with packages)
    if result.critical_risk_count > 0:
        result.overall_deprecation_risk = DeprecationRiskLevel.CRITICAL
    elif result.high_risk_count > 0:
        result.overall_deprecation_risk = DeprecationRiskLevel.HIGH
    elif result.moderate_risk_count > 0:
        result.overall_deprecation_risk = DeprecationRiskLevel.MODERATE
    else:
        result.overall_deprecation_risk = DeprecationRiskLevel.LOW

    return result


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_RISK_STYLES: dict[DeprecationRiskLevel, tuple[str, str]] = {
    DeprecationRiskLevel.LOW: ("✓", "green"),
    DeprecationRiskLevel.MODERATE: ("⚠", "yellow"),
    DeprecationRiskLevel.HIGH: ("!", "red"),
    DeprecationRiskLevel.CRITICAL: ("✗", "red bold"),
}

_CADENCE_STYLES: dict[ReleaseCadence, str] = {
    ReleaseCadence.VERY_FREQUENT: "green",
    ReleaseCadence.FREQUENT: "green",
    ReleaseCadence.REGULAR: "cyan",
    ReleaseCadence.INFREQUENT: "yellow",
    ReleaseCadence.RARE: "yellow",
    ReleaseCadence.STALLED: "red",
}


def render_predict_table(result: PredictResult, console: Console | None = None) -> None:
    """Render predict results as a Rich table.

    Args:
        result: The predict analysis result.
        console: Rich console instance.
    """
    if console is None:
        console = Console()

    # Header
    console.print()
    overall_icon, overall_color = _RISK_STYLES.get(result.overall_deprecation_risk, ("?", "white"))
    console.print(
        f"[bold]depcheck predict[/bold] — Deprecation Risk Analysis for "
        f"[cyan]{result.project_path}[/cyan]"
    )
    console.print(
        f" Overall risk: [{overall_color}]{overall_icon} "
        f"{result.overall_deprecation_risk.value}[/{overall_color}]"
    )
    console.print()

    # Summary table
    summary = Table(title="Risk Summary", show_lines=False, pad_edge=False)
    summary.add_column("Risk Level", style="bold")
    summary.add_column("Count", justify="right")
    summary.add_column("Percentage", justify="right")

    for level in DeprecationRiskLevel:
        count_map = {
            DeprecationRiskLevel.LOW: result.low_risk_count,
            DeprecationRiskLevel.MODERATE: result.moderate_risk_count,
            DeprecationRiskLevel.HIGH: result.high_risk_count,
            DeprecationRiskLevel.CRITICAL: result.critical_risk_count,
        }
        count = count_map[level]
        icon, color = _RISK_STYLES.get(level, ("?", "white"))
        pct = f"{count / result.total_packages * 100:.0f}%" if result.total_packages > 0 else "0%"
        summary.add_row(f"[{color}]{icon} {level.value}[/{color}]", str(count), pct)

    console.print(summary)
    console.print()

    # Package details table
    pkg_table = Table(title="Package Predictions", show_lines=True, pad_edge=False)
    pkg_table.add_column("Package", style="bold", max_width=25)
    pkg_table.add_column("Installed", max_width=14)
    pkg_table.add_column("Health", justify="center")
    pkg_table.add_column("Cadence", justify="center")
    pkg_table.add_column("Deprecation Risk", justify="center")
    pkg_table.add_column("Score", justify="right", max_width=6)
    pkg_table.add_column("Signals", justify="right", max_width=7)
    pkg_table.add_column("Next Version (est.)", max_width=20)

    _status_styles: dict[HealthStatus, tuple[str, str]] = {
        HealthStatus.HEALTHY: ("✓", "green"),
        HealthStatus.OUTDATED: ("↑", "yellow"),
        HealthStatus.VULNERABLE: ("!", "red bold"),
        HealthStatus.UNMAINTAINED: ("⚠", "yellow"),
        HealthStatus.YANKED: ("✗", "red"),
        HealthStatus.REMOVED: ("✗", "red"),
        HealthStatus.UNKNOWN: ("?", "dim"),
    }

    for pred in result.packages:
        # Health status
        icon, color = _status_styles.get(pred.health_status, ("?", "white"))
        health_str = f"[{color}]{icon}[/{color}]"

        # Cadence
        cadence_str = "—"
        if pred.release_pattern:
            cadence = pred.release_pattern.cadence
            cad_color = _CADENCE_STYLES.get(cadence, "white")
            cadence_str = f"[{cad_color}]{cadence.value}[/{cad_color}]"

        # Risk
        risk_icon, risk_color = _RISK_STYLES.get(pred.deprecation_risk, ("?", "white"))
        risk_str = f"[{risk_color}]{risk_icon} {pred.deprecation_risk.value}[/{risk_color}]"

        # Signals count
        signals_count = (
            str(pred.deprecation_signals.signal_count) if pred.deprecation_signals else "0"
        )

        # Next version estimate
        next_ver = "—"
        if pred.version_prediction and pred.version_prediction.predicted_next_minor:
            next_ver = pred.version_prediction.predicted_next_minor
            if pred.version_prediction.estimated_days_to_next:
                next_ver += f" (~{pred.version_prediction.estimated_days_to_next:.0f}d)"

        pkg_table.add_row(
            pred.package_name,
            pred.installed_version or "—",
            health_str,
            cadence_str,
            risk_str,
            f"{pred.deprecation_risk_score:.0f}",
            signals_count,
            next_ver,
        )

    console.print(pkg_table)

    # Deprecation signals detail for at-risk packages
    at_risk = [
        p
        for p in result.packages
        if p.deprecation_risk in (DeprecationRiskLevel.HIGH, DeprecationRiskLevel.CRITICAL)
    ]
    if at_risk:
        console.print()
        console.print("[bold red]⚠ Deprecation Signals Detail[/bold red]")
        for pred in at_risk:
            if pred.deprecation_signals and pred.deprecation_signals.signal_details:
                console.print(
                    f"\n  [bold]{pred.package_name}[/bold] "
                    f"(score: {pred.deprecation_risk_score:.0f})"
                )
                for detail in pred.deprecation_signals.signal_details:
                    console.print(f"    [red]•[/red] {detail}")


def render_predict_json(result: PredictResult, console: Console | None = None) -> None:
    """Render predict results as JSON.

    Args:
        result: The predict analysis result.
        console: Rich console instance.
    """
    if console is None:
        console = Console(force_terminal=False, no_color=True)

    console.print(json.dumps(result.to_dict(), indent=2))
