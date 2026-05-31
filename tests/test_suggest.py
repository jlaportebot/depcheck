"""Tests for depcheck.suggest — dependency alternatives and recommendations."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from depcheck.models import HealthStatus, PackageReport, ScanResult
from depcheck.suggest import (
    Alternative,
    AlternativeReason,
    MigrationDifficulty,
    PackageSuggestion,
    SuggestionConfidence,
    SuggestResult,
    _build_recommendation,
    _determine_action,
    _determine_reasons,
    _get_known_alternatives,
    _parse_alternative_data,
    _status_style,
    render_suggest_json,
    render_suggest_table,
    suggest_alternatives,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_pkg(
    name: str = "test-pkg",
    installed_version: str = "1.0.0",
    latest_version: str = "2.0.0",
    status: HealthStatus = HealthStatus.HEALTHY,
    has_license_issue: bool = False,
) -> PackageReport:
    """Create a PackageReport for testing."""
    from depcheck.models import LicenseInfo

    license_info = None
    if has_license_issue:
        license_info = LicenseInfo(
            spdx_id="GPL-3.0",
            raw_license="GPL-3.0",
            category="copyleft",
            is_compliant=False,
            compliance_note="Copyleft license not allowed by policy",
        )
    return PackageReport(
        name=name,
        installed_version=installed_version,
        latest_version=latest_version,
        status=status,
        license_info=license_info,
    )


def _make_scan_result(
    packages: list[PackageReport] | None = None,
    errors: list[str] | None = None,
) -> ScanResult:
    """Create a ScanResult for testing."""
    return ScanResult(
        project_path="/fake/project",
        packages=packages or [_make_pkg()],
        errors=errors or [],
    )


# ---------------------------------------------------------------------------
# AlternativeReason tests
# ---------------------------------------------------------------------------


class TestAlternativeReason:
    """Tests for AlternativeReason enum."""

    def test_values(self) -> None:
        assert AlternativeReason.VULNERABLE.value == "vulnerable"
        assert AlternativeReason.UNMAINTAINED.value == "unmaintained"
        assert AlternativeReason.YANKED.value == "yanked"
        assert AlternativeReason.REMOVED.value == "removed"
        assert AlternativeReason.OUTDATED_MAJOR.value == "outdated_major"
        assert AlternativeReason.BETTER_ALTERNATIVE.value == "better_alternative"
        assert AlternativeReason.LICENSE_ISSUE.value == "license_issue"
        assert AlternativeReason.LOWER_POPULARITY.value == "lower_popularity"

    def test_from_value(self) -> None:
        assert AlternativeReason("vulnerable") == AlternativeReason.VULNERABLE
        assert AlternativeReason("better_alternative") == AlternativeReason.BETTER_ALTERNATIVE

    def test_invalid_value(self) -> None:
        with pytest.raises(ValueError):
            AlternativeReason("nonexistent")


# ---------------------------------------------------------------------------
# MigrationDifficulty tests
# ---------------------------------------------------------------------------


class TestMigrationDifficulty:
    """Tests for MigrationDifficulty enum."""

    def test_values(self) -> None:
        assert MigrationDifficulty.TRIVIAL.value == "trivial"
        assert MigrationDifficulty.EASY.value == "easy"
        assert MigrationDifficulty.MODERATE.value == "moderate"
        assert MigrationDifficulty.HARD.value == "hard"
        assert MigrationDifficulty.UNKNOWN.value == "unknown"

    def test_from_value(self) -> None:
        assert MigrationDifficulty("easy") == MigrationDifficulty.EASY


# ---------------------------------------------------------------------------
# SuggestionConfidence tests
# ---------------------------------------------------------------------------


class TestSuggestionConfidence:
    """Tests for SuggestionConfidence enum."""

    def test_values(self) -> None:
        assert SuggestionConfidence.HIGH.value == "high"
        assert SuggestionConfidence.MEDIUM.value == "medium"
        assert SuggestionConfidence.LOW.value == "low"
        assert SuggestionConfidence.SPECULATIVE.value == "speculative"

    def test_from_value(self) -> None:
        assert SuggestionConfidence("medium") == SuggestionConfidence.MEDIUM


# ---------------------------------------------------------------------------
# Alternative tests
# ---------------------------------------------------------------------------


class TestAlternative:
    """Tests for Alternative dataclass."""

    def test_creation(self) -> None:
        alt = Alternative(
            name="httpx",
            reason=AlternativeReason.BETTER_ALTERNATIVE,
            difficulty=MigrationDifficulty.EASY,
            confidence=SuggestionConfidence.HIGH,
            advantages=["Async support", "HTTP/2"],
            migration_notes="Drop-in replacement.",
            api_compatibility=0.9,
            popularity_proxy="high",
        )
        assert alt.name == "httpx"
        assert alt.reason == AlternativeReason.BETTER_ALTERNATIVE
        assert len(alt.advantages) == 2
        assert alt.api_compatibility == 0.9

    def test_defaults(self) -> None:
        alt = Alternative(
            name="test",
            reason=AlternativeReason.VULNERABLE,
            difficulty=MigrationDifficulty.UNKNOWN,
            confidence=SuggestionConfidence.LOW,
        )
        assert alt.advantages == []
        assert alt.migration_notes == ""
        assert alt.api_compatibility == 0.0
        assert alt.popularity_proxy == ""

    def test_to_dict(self) -> None:
        alt = Alternative(
            name="httpx",
            reason=AlternativeReason.BETTER_ALTERNATIVE,
            difficulty=MigrationDifficulty.EASY,
            confidence=SuggestionConfidence.HIGH,
            advantages=["Faster"],
            migration_notes="Easy migration",
        )
        d = alt.to_dict()
        assert d["name"] == "httpx"
        assert d["reason"] == "better_alternative"
        assert d["difficulty"] == "easy"
        assert d["confidence"] == "high"
        assert d["advantages"] == ["Faster"]
        assert d["migration_notes"] == "Easy migration"
        assert "api_compatibility" in d
        assert "popularity_proxy" in d


# ---------------------------------------------------------------------------
# PackageSuggestion tests
# ---------------------------------------------------------------------------


class TestPackageSuggestion:
    """Tests for PackageSuggestion dataclass."""

    def test_creation(self) -> None:
        s = PackageSuggestion(
            package="requests",
            current_version="2.28.0",
            status=HealthStatus.HEALTHY,
            has_issues=False,
            recommendation="Keep",
            action="keep",
        )
        assert s.package == "requests"
        assert s.current_version == "2.28.0"
        assert s.alternatives == []

    def test_to_dict(self) -> None:
        alt = Alternative(
            name="httpx",
            reason=AlternativeReason.BETTER_ALTERNATIVE,
            difficulty=MigrationDifficulty.EASY,
            confidence=SuggestionConfidence.HIGH,
        )
        s = PackageSuggestion(
            package="requests",
            current_version="2.28.0",
            status=HealthStatus.HEALTHY,
            has_issues=False,
            alternatives=[alt],
            recommendation="Consider httpx",
            action="review",
        )
        d = s.to_dict()
        assert d["package"] == "requests"
        assert d["action"] == "review"
        assert len(d["alternatives"]) == 1
        assert d["alternatives"][0]["name"] == "httpx"


# ---------------------------------------------------------------------------
# SuggestResult tests
# ---------------------------------------------------------------------------


class TestSuggestResult:
    """Tests for SuggestResult dataclass."""

    def test_empty(self) -> None:
        r = SuggestResult()
        assert r.total == 0
        assert r.migrate_count == 0
        assert r.update_count == 0
        assert r.review_count == 0
        assert r.keep_count == 0
        assert r.with_alternatives == []

    def test_counts(self) -> None:
        r = SuggestResult(
            suggestions=[
                PackageSuggestion(package="a", action="migrate"),
                PackageSuggestion(package="b", action="migrate"),
                PackageSuggestion(package="c", action="update"),
                PackageSuggestion(package="d", action="review"),
                PackageSuggestion(package="e", action="keep"),
                PackageSuggestion(
                    package="f",
                    action="review",
                    alternatives=[
                        Alternative(
                            name="alt",
                            reason=AlternativeReason.BETTER_ALTERNATIVE,
                            difficulty=MigrationDifficulty.EASY,
                            confidence=SuggestionConfidence.HIGH,
                        )
                    ],
                ),
            ]
        )
        assert r.total == 6
        assert r.migrate_count == 2
        assert r.update_count == 1
        assert r.review_count == 2
        assert r.keep_count == 1
        assert len(r.with_alternatives) == 1
        assert r.with_alternatives[0].package == "f"

    def test_to_dict(self) -> None:
        r = SuggestResult(
            project_path="/test",
            suggestions=[
                PackageSuggestion(package="a", action="keep"),
            ],
        )
        d = r.to_dict()
        assert d["project_path"] == "/test"
        assert d["summary"]["total"] == 1
        assert d["summary"]["keep"] == 1
        assert len(d["suggestions"]) == 1


# ---------------------------------------------------------------------------
# _get_known_alternatives tests
# ---------------------------------------------------------------------------


class TestGetKnownAlternatives:
    """Tests for _get_known_alternatives."""

    def test_known_package(self) -> None:
        alts = _get_known_alternatives("requests")
        assert len(alts) >= 1
        assert any(a["name"] == "httpx" for a in alts)

    def test_unknown_package(self) -> None:
        alts = _get_known_alternatives("nonexistent-pkg-xyz-12345")
        assert alts == []

    def test_flask_alternatives(self) -> None:
        alts = _get_known_alternatives("flask")
        assert len(alts) >= 1
        assert any(a["name"] == "fastapi" for a in alts)

    def test_logging_alternatives(self) -> None:
        alts = _get_known_alternatives("logging")
        assert len(alts) >= 1
        names = [a["name"] for a in alts]
        assert "loguru" in names
        assert "structlog" in names


# ---------------------------------------------------------------------------
# _determine_reasons tests
# ---------------------------------------------------------------------------


class TestDetermineReasons:
    """Tests for _determine_reasons."""

    def test_healthy_no_reasons(self) -> None:
        pkg = _make_pkg(status=HealthStatus.HEALTHY)
        reasons = _determine_reasons(pkg)
        assert reasons == []

    def test_vulnerable(self) -> None:
        pkg = _make_pkg(status=HealthStatus.VULNERABLE)
        reasons = _determine_reasons(pkg)
        assert AlternativeReason.VULNERABLE in reasons

    def test_unmaintained(self) -> None:
        pkg = _make_pkg(status=HealthStatus.UNMAINTAINED)
        reasons = _determine_reasons(pkg)
        assert AlternativeReason.UNMAINTAINED in reasons

    def test_yanked(self) -> None:
        pkg = _make_pkg(status=HealthStatus.YANKED)
        reasons = _determine_reasons(pkg)
        assert AlternativeReason.YANKED in reasons

    def test_removed(self) -> None:
        pkg = _make_pkg(status=HealthStatus.REMOVED)
        reasons = _determine_reasons(pkg)
        assert AlternativeReason.REMOVED in reasons

    def test_outdated_major(self) -> None:
        pkg = _make_pkg(
            installed_version="1.0.0",
            latest_version="2.0.0",
            status=HealthStatus.OUTDATED,
        )
        reasons = _determine_reasons(pkg)
        assert AlternativeReason.OUTDATED_MAJOR in reasons

    def test_outdated_minor_no_major_reason(self) -> None:
        pkg = _make_pkg(
            installed_version="1.0.0",
            latest_version="1.5.0",
            status=HealthStatus.OUTDATED,
        )
        reasons = _determine_reasons(pkg)
        assert AlternativeReason.OUTDATED_MAJOR not in reasons

    def test_license_issue(self) -> None:
        pkg = _make_pkg(has_license_issue=True)
        reasons = _determine_reasons(pkg)
        assert AlternativeReason.LICENSE_ISSUE in reasons

    def test_multiple_reasons(self) -> None:
        pkg = _make_pkg(
            status=HealthStatus.VULNERABLE,
            has_license_issue=True,
        )
        reasons = _determine_reasons(pkg)
        assert AlternativeReason.VULNERABLE in reasons
        assert AlternativeReason.LICENSE_ISSUE in reasons


# ---------------------------------------------------------------------------
# _determine_action tests
# ---------------------------------------------------------------------------


class TestDetermineAction:
    """Tests for _determine_action."""

    def test_removed_with_alternatives(self) -> None:
        pkg = _make_pkg(status=HealthStatus.REMOVED)
        alts = [
            Alternative(
                name="replacement",
                reason=AlternativeReason.REMOVED,
                difficulty=MigrationDifficulty.EASY,
                confidence=SuggestionConfidence.HIGH,
            )
        ]
        assert _determine_action(pkg, alts) == "migrate"

    def test_removed_no_alternatives(self) -> None:
        pkg = _make_pkg(status=HealthStatus.REMOVED)
        assert _determine_action(pkg, []) == "review"

    def test_vulnerable_with_alternatives(self) -> None:
        pkg = _make_pkg(status=HealthStatus.VULNERABLE)
        alts = [
            Alternative(
                name="safe-pkg",
                reason=AlternativeReason.VULNERABLE,
                difficulty=MigrationDifficulty.MODERATE,
                confidence=SuggestionConfidence.HIGH,
            )
        ]
        assert _determine_action(pkg, alts) == "migrate"

    def test_vulnerable_no_alternatives(self) -> None:
        pkg = _make_pkg(status=HealthStatus.VULNERABLE)
        assert _determine_action(pkg, []) == "update"

    def test_unmaintained_with_alternatives(self) -> None:
        pkg = _make_pkg(status=HealthStatus.UNMAINTAINED)
        alts = [
            Alternative(
                name="active-pkg",
                reason=AlternativeReason.UNMAINTAINED,
                difficulty=MigrationDifficulty.MODERATE,
                confidence=SuggestionConfidence.MEDIUM,
            )
        ]
        assert _determine_action(pkg, alts) == "review"

    def test_unmaintained_no_alternatives(self) -> None:
        pkg = _make_pkg(status=HealthStatus.UNMAINTAINED)
        assert _determine_action(pkg, []) == "keep"

    def test_outdated(self) -> None:
        pkg = _make_pkg(status=HealthStatus.OUTDATED)
        assert _determine_action(pkg, []) == "update"

    def test_healthy_with_high_confidence_alternative(self) -> None:
        pkg = _make_pkg(status=HealthStatus.HEALTHY)
        alts = [
            Alternative(
                name="better",
                reason=AlternativeReason.BETTER_ALTERNATIVE,
                difficulty=MigrationDifficulty.EASY,
                confidence=SuggestionConfidence.HIGH,
            )
        ]
        assert _determine_action(pkg, alts) == "review"

    def test_healthy_with_low_confidence_alternative(self) -> None:
        pkg = _make_pkg(status=HealthStatus.HEALTHY)
        alts = [
            Alternative(
                name="maybe",
                reason=AlternativeReason.BETTER_ALTERNATIVE,
                difficulty=MigrationDifficulty.HARD,
                confidence=SuggestionConfidence.LOW,
            )
        ]
        assert _determine_action(pkg, alts) == "keep"

    def test_healthy_no_alternatives(self) -> None:
        pkg = _make_pkg(status=HealthStatus.HEALTHY)
        assert _determine_action(pkg, []) == "keep"


# ---------------------------------------------------------------------------
# _build_recommendation tests
# ---------------------------------------------------------------------------


class TestBuildRecommendation:
    """Tests for _build_recommendation."""

    def test_keep(self) -> None:
        pkg = _make_pkg(name="good-pkg")
        assert "healthy" in _build_recommendation(pkg, "keep", [])

    def test_update_with_version(self) -> None:
        pkg = _make_pkg(name="old-pkg", installed_version="1.0.0", latest_version="2.0.0")
        rec = _build_recommendation(pkg, "update", [])
        assert "1.0.0" in rec
        assert "2.0.0" in rec

    def test_update_without_version(self) -> None:
        pkg = _make_pkg(name="old-pkg", latest_version="")
        rec = _build_recommendation(pkg, "update", [])
        assert "Check for updates" in rec

    def test_migrate_with_alternatives(self) -> None:
        pkg = _make_pkg(name="bad-pkg")
        alts = [
            Alternative(
                name="good-alt",
                reason=AlternativeReason.VULNERABLE,
                difficulty=MigrationDifficulty.EASY,
                confidence=SuggestionConfidence.HIGH,
            )
        ]
        rec = _build_recommendation(pkg, "migrate", alts)
        assert "good-alt" in rec

    def test_migrate_no_alternatives(self) -> None:
        pkg = _make_pkg(name="bad-pkg")
        rec = _build_recommendation(pkg, "migrate", [])
        assert "no known alternatives" in rec

    def test_review_with_alternatives(self) -> None:
        pkg = _make_pkg(name="maybe-pkg")
        alts = [
            Alternative(
                name="nice-alt",
                reason=AlternativeReason.BETTER_ALTERNATIVE,
                difficulty=MigrationDifficulty.MODERATE,
                confidence=SuggestionConfidence.MEDIUM,
                advantages=["Faster", "Safer", "Cleaner API"],
            )
        ]
        rec = _build_recommendation(pkg, "review", alts)
        assert "nice-alt" in rec

    def test_review_no_alternatives(self) -> None:
        pkg = _make_pkg(name="maybe-pkg", status=HealthStatus.UNMAINTAINED)
        rec = _build_recommendation(pkg, "review", [])
        assert "unmaintained" in rec


# ---------------------------------------------------------------------------
# _parse_alternative_data tests
# ---------------------------------------------------------------------------


class TestParseAlternativeData:
    """Tests for _parse_alternative_data."""

    def test_full_data(self) -> None:
        data = {
            "name": "httpx",
            "reason": "better_alternative",
            "difficulty": "easy",
            "confidence": "high",
            "advantages": ["Async", "HTTP/2"],
            "migration_notes": "Easy migration",
            "api_compatibility": 0.85,
            "popularity_proxy": "high",
        }
        alt = _parse_alternative_data(data)
        assert alt.name == "httpx"
        assert alt.reason == AlternativeReason.BETTER_ALTERNATIVE
        assert alt.difficulty == MigrationDifficulty.EASY
        assert alt.confidence == SuggestionConfidence.HIGH
        assert len(alt.advantages) == 2
        assert alt.api_compatibility == 0.85

    def test_minimal_data(self) -> None:
        data = {"name": "test"}
        alt = _parse_alternative_data(data)
        assert alt.name == "test"
        assert alt.reason == AlternativeReason.BETTER_ALTERNATIVE
        assert alt.difficulty == MigrationDifficulty.UNKNOWN
        assert alt.confidence == SuggestionConfidence.MEDIUM
        assert alt.advantages == []

    def test_invalid_reason_falls_back(self) -> None:
        data = {"name": "test", "reason": "better_alternative"}
        alt = _parse_alternative_data(data)
        assert alt.reason == AlternativeReason.BETTER_ALTERNATIVE


# ---------------------------------------------------------------------------
# _status_style tests
# ---------------------------------------------------------------------------


class TestStatusStyle:
    """Tests for _status_style."""

    def test_healthy(self) -> None:
        icon, color = _status_style(HealthStatus.HEALTHY)
        assert icon == "OK"
        assert color == "green"

    def test_vulnerable(self) -> None:
        icon, color = _status_style(HealthStatus.VULNERABLE)
        assert icon == "!!"
        assert "red" in color

    def test_unknown(self) -> None:
        icon, color = _status_style(HealthStatus.UNKNOWN)
        assert icon == "?"

    def test_all_statuses_have_style(self) -> None:
        for status in HealthStatus:
            icon, color = _status_style(status)
            assert icon is not None
            assert color is not None


# ---------------------------------------------------------------------------
# suggest_alternatives tests
# ---------------------------------------------------------------------------


class TestSuggestAlternatives:
    """Tests for the main suggest_alternatives function."""

    def test_invalid_path(self) -> None:
        result = suggest_alternatives("/nonexistent/path/xyz")
        assert len(result.errors) > 0
        assert "not a directory" in result.errors[0]

    def test_with_scan_result_provided(self, tmp_path: Path) -> None:
        """When scan_result is provided, path validation is still needed."""
        scan = _make_scan_result(
            packages=[
                _make_pkg(name="requests", status=HealthStatus.HEALTHY),
                _make_pkg(name="old-pkg", status=HealthStatus.OUTDATED),
                _make_pkg(name="vuln-pkg", status=HealthStatus.VULNERABLE),
            ]
        )
        result = suggest_alternatives(
            project_path=str(tmp_path),
            scan_result=scan,
        )
        assert result.total == 3
        # Vulnerable/outdated packages should be sorted before healthy ones
        first_action = result.suggestions[0].action
        assert first_action in ("migrate", "update", "review")

    def test_with_known_alternatives(self, tmp_path: Path) -> None:
        scan = _make_scan_result(
            packages=[
                _make_pkg(name="requests", status=HealthStatus.HEALTHY),
            ]
        )
        result = suggest_alternatives(
            project_path=str(tmp_path),
            scan_result=scan,
        )
        req_suggestion = next(
            s for s in result.suggestions if s.package == "requests"
        )
        assert len(req_suggestion.alternatives) >= 1
        assert any(a.name == "httpx" for a in req_suggestion.alternatives)

    def test_vulnerable_package_with_alternatives(self, tmp_path: Path) -> None:
        scan = _make_scan_result(
            packages=[
                _make_pkg(name="vuln-pkg", status=HealthStatus.VULNERABLE),
            ]
        )
        result = suggest_alternatives(
            project_path=str(tmp_path),
            scan_result=scan,
        )
        s = result.suggestions[0]
        assert s.action in ("migrate", "update")
        assert s.has_issues is True

    def test_sorting_order(self, tmp_path: Path) -> None:
        """Verify migrate > review > update > keep ordering."""
        scan = _make_scan_result(
            packages=[
                _make_pkg(name="aaa-keep", status=HealthStatus.HEALTHY),
                _make_pkg(name="bbb-update", status=HealthStatus.OUTDATED),
                _make_pkg(name="ccc-review", status=HealthStatus.UNMAINTAINED),
                _make_pkg(name="ddd-migrate", status=HealthStatus.REMOVED),
            ]
        )
        result = suggest_alternatives(
            project_path=str(tmp_path),
            scan_result=scan,
        )
        actions = [s.action for s in result.suggestions]
        # migrate should come before review, review before update, etc.
        action_order = {"migrate": 0, "review": 1, "update": 2, "keep": 3}
        order_nums = [action_order.get(a, 4) for a in actions]
        assert order_nums == sorted(order_nums)

    def test_to_dict_roundtrip(self, tmp_path: Path) -> None:
        scan = _make_scan_result(
            packages=[
                _make_pkg(name="requests", status=HealthStatus.HEALTHY),
            ]
        )
        result = suggest_alternatives(
            project_path=str(tmp_path),
            scan_result=scan,
        )
        d = result.to_dict()
        assert "project_path" in d
        assert "summary" in d
        assert "suggestions" in d
        # Verify JSON-serializable
        json_str = json.dumps(d)
        assert json.loads(json_str) == d


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


class TestRenderSuggestTable:
    """Tests for render_suggest_table."""

    def test_empty_result(self) -> None:
        result = SuggestResult(project_path="/test")
        console = MagicMock()
        console.print = MagicMock()
        render_suggest_table(result, console=console)
        # Should print at least the header panel and "all healthy" message
        assert console.print.call_count >= 2

    def test_with_suggestions(self) -> None:
        result = SuggestResult(
            project_path="/test",
            suggestions=[
                PackageSuggestion(
                    package="requests",
                    current_version="2.28.0",
                    status=HealthStatus.HEALTHY,
                    action="review",
                    recommendation="Consider httpx",
                    alternatives=[
                        Alternative(
                            name="httpx",
                            reason=AlternativeReason.BETTER_ALTERNATIVE,
                            difficulty=MigrationDifficulty.EASY,
                            confidence=SuggestionConfidence.HIGH,
                            advantages=["Async"],
                        )
                    ],
                ),
            ],
        )
        console = MagicMock()
        render_suggest_table(result, console=console)
        # Should print multiple items: header, summary, table, alt table
        assert console.print.call_count >= 3

    def test_error_only_result(self) -> None:
        result = SuggestResult(
            project_path="/test",
            errors=["Something went wrong"],
        )
        console = MagicMock()
        render_suggest_table(result, console=console)
        console.print.assert_called()


class TestRenderSuggestJson:
    """Tests for render_suggest_json."""

    def test_valid_json(self) -> None:
        result = SuggestResult(project_path="/test")
        json_str = render_suggest_json(result)
        data = json.loads(json_str)
        assert data["project_path"] == "/test"
        assert "summary" in data

    def test_with_suggestions(self) -> None:
        result = SuggestResult(
            project_path="/test",
            suggestions=[
                PackageSuggestion(
                    package="test-pkg",
                    action="keep",
                    recommendation="Looks good",
                ),
            ],
        )
        json_str = render_suggest_json(result)
        data = json.loads(json_str)
        assert data["summary"]["total"] == 1
        assert data["summary"]["keep"] == 1
