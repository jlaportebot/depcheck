"""Tests for depcheck.scorecard — dependency health scorecard and grading."""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch

from depcheck.scorecard import (
    Grade,
    CategoryScore,
    ScoreCategory,
    ScorecardResult,
    _calculate_grade,
    _GRADE_THRESHOLDS,
    DEFAULT_WEIGHTS,
    _score_security,
    _score_freshness,
    _score_pinning,
    _score_licenses,
    _score_size,
    _score_maintenance,
    build_scorecard,
    generate_badge_url,
    generate_markdown_report,
    render_scorecard,
    render_scorecard_json,
)


# ── Grade Tests ──────────────────────────────────────────────────────────


class TestGrade:
    """Tests for the Grade enum."""

    def test_all_grades(self) -> None:
        assert Grade.A_PLUS.value == "A+"
        assert Grade.A.value == "A"
        assert Grade.B.value == "B"
        assert Grade.C.value == "C"
        assert Grade.D.value == "D"
        assert Grade.F.value == "F"

    def test_from_score_a_plus(self) -> None:
        assert _calculate_grade(98) == Grade.A_PLUS

    def test_from_score_a(self) -> None:
        assert _calculate_grade(90) == Grade.A

    def test_from_score_b(self) -> None:
        assert _calculate_grade(75) == Grade.B

    def test_from_score_c(self) -> None:
        assert _calculate_grade(58) == Grade.C

    def test_from_score_d(self) -> None:
        assert _calculate_grade(42) == Grade.D

    def test_from_score_f(self) -> None:
        assert _calculate_grade(20) == Grade.F

    def test_from_score_boundaries(self) -> None:
        assert _calculate_grade(95) == Grade.A_PLUS
        assert _calculate_grade(94.9) == Grade.A
        assert _calculate_grade(85) == Grade.A
        assert _calculate_grade(84.9) == Grade.B
        assert _calculate_grade(70) == Grade.B
        assert _calculate_grade(69.9) == Grade.C
        assert _calculate_grade(55) == Grade.C
        assert _calculate_grade(54.9) == Grade.D
        assert _calculate_grade(40) == Grade.D
        assert _calculate_grade(0) == Grade.F
        assert _calculate_grade(100) == Grade.A_PLUS

    def test_from_score_negative(self) -> None:
        assert _calculate_grade(-5) == Grade.F


# ── Grade Thresholds Tests ───────────────────────────────────────────────


class TestGradeThresholds:
    """Tests for _GRADE_THRESHOLDS."""

    def test_sorted_descending(self) -> None:
        scores = [t[0] for t in _GRADE_THRESHOLDS]
        assert scores == sorted(scores, reverse=True)

    def test_covers_all_grades(self) -> None:
        grades = [t[1] for t in _GRADE_THRESHOLDS]
        assert Grade.A_PLUS in grades
        assert Grade.F in grades

    def test_starts_at_95(self) -> None:
        assert _GRADE_THRESHOLDS[0][0] == 95

    def test_ends_at_0(self) -> None:
        assert _GRADE_THRESHOLDS[-1][0] == 0


# ── Default Weights Tests ────────────────────────────────────────────────


class TestDefaultWeights:
    """Tests for DEFAULT_WEIGHTS."""

    def test_sum_to_one(self) -> None:
        total = sum(DEFAULT_WEIGHTS.values())
        assert total == pytest.approx(1.0)

    def test_all_categories_present(self) -> None:
        for cat in ScoreCategory:
            assert cat.value in DEFAULT_WEIGHTS

    def test_security_highest_weight(self) -> None:
        assert DEFAULT_WEIGHTS["security"] >= max(
            v for k, v in DEFAULT_WEIGHTS.items() if k != "security"
        )


# ── ScoreCategory Tests ──────────────────────────────────────────────────


class TestScoreCategory:
    """Tests for the ScoreCategory enum."""

    def test_all_values(self) -> None:
        assert ScoreCategory.SECURITY.value == "security"
        assert ScoreCategory.FRESHNESS.value == "freshness"
        assert ScoreCategory.PINNING.value == "pinning"
        assert ScoreCategory.LICENSES.value == "licenses"
        assert ScoreCategory.SIZE.value == "size"
        assert ScoreCategory.MAINTENANCE.value == "maintenance"

    def test_count(self) -> None:
        assert len(ScoreCategory) == 6


# ── CategoryScore Tests ──────────────────────────────────────────────────


class TestCategoryScore:
    """Tests for the CategoryScore dataclass."""

    def test_basic_creation(self) -> None:
        cs = CategoryScore(category="security", score=85.0, weight=0.3, weighted_score=25.5)
        assert cs.category == "security"
        assert cs.score == 85.0
        assert cs.weight == 0.3
        assert cs.weighted_score == 25.5
        assert cs.details == ""
        assert cs.suggestions == []

    def test_with_details_and_suggestions(self) -> None:
        cs = CategoryScore(
            category="security",
            score=60.0,
            weight=0.3,
            weighted_score=18.0,
            details="2 critical vulnerabilities",
            suggestions=["Update pkg-a to fix CVE-2024-0001"],
        )
        assert cs.details == "2 critical vulnerabilities"
        assert len(cs.suggestions) == 1
        assert "CVE" in cs.suggestions[0]

    def test_from_enum_value(self) -> None:
        cs = CategoryScore(category=ScoreCategory.SECURITY.value, score=90.0)
        assert cs.category == "security"


# ── ScorecardResult Tests ────────────────────────────────────────────────


class TestScorecardResult:
    """Tests for the ScorecardResult dataclass."""

    def test_defaults(self) -> None:
        result = ScorecardResult(project_path="/test")
        assert result.project_path == "/test"
        assert result.overall_score == 0.0
        assert result.grade == Grade.F
        assert result.category_scores == []
        assert result.top_suggestions == []

    def test_with_scores(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=85.0,
            grade=Grade.A,
            category_scores=[
                CategoryScore(category="security", score=90.0, weight=0.3, weighted_score=27.0),
                CategoryScore(category="freshness", score=80.0, weight=0.2, weighted_score=16.0),
            ],
        )
        assert result.overall_score == 85.0
        assert result.grade == Grade.A
        assert len(result.category_scores) == 2


# ── Individual Scoring Function Tests ────────────────────────────────────


class TestScoreSecurity:
    """Tests for _score_security."""

    def test_no_packages(self) -> None:
        from depcheck.models import ScanResult
        scan = ScanResult(project_path="/test", packages=[])
        cs = _score_security(scan)
        assert cs.score == 100.0  # No packages = no vulnerabilities

    def test_with_packages(self) -> None:
        from depcheck.models import PackageReport, ScanResult
        scan = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="requests", installed_version="2.31.0"),
            ],
        )
        cs = _score_security(scan)
        assert 0 <= cs.score <= 100
        assert cs.category == "security"


class TestScoreFreshness:
    """Tests for _score_freshness."""

    def test_no_packages(self) -> None:
        from depcheck.models import ScanResult
        scan = ScanResult(project_path="/test", packages=[])
        cs = _score_freshness(scan)
        assert cs.score == 100.0

    def test_with_packages(self) -> None:
        from depcheck.models import PackageReport, ScanResult
        scan = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="requests", installed_version="2.31.0"),
            ],
        )
        cs = _score_freshness(scan)
        assert 0 <= cs.score <= 100
        assert cs.category == "freshness"


class TestScorePinning:
    """Tests for _score_pinning."""

    @patch("depcheck.scorecard.build_pin_report")
    def test_pinning_score(self, mock_pin: MagicMock) -> None:
        from depcheck.pinpoint import PinReport
        mock_pin.return_value = PinReport(
            project_path="/test", total_dependencies=5, pinned_count=4, health_score=80.0,
        )
        cs = _score_pinning("/test")
        assert 0 <= cs.score <= 100
        assert cs.category == "pinning"


class TestScoreLicenses:
    """Tests for _score_licenses."""

    def test_no_packages(self) -> None:
        from depcheck.models import ScanResult
        scan = ScanResult(project_path="/test", packages=[])
        cs = _score_licenses(scan)
        assert cs.score >= 0
        assert cs.category == "licenses"


class TestScoreSize:
    """Tests for _score_size."""

    @patch("depcheck.scorecard.build_size_report")
    def test_size_score(self, mock_size: MagicMock) -> None:
        from depcheck.depsize import SizeReport
        from depcheck.models import ScanResult
        mock_size.return_value = SizeReport(project_path="/test")
        scan = ScanResult(project_path="/test", packages=[])
        cs = _score_size("/test", scan)
        assert cs.score >= 0
        assert cs.category == "size"


class TestScoreMaintenance:
    """Tests for _score_maintenance."""

    def test_no_packages(self) -> None:
        from depcheck.models import ScanResult
        scan = ScanResult(project_path="/test", packages=[])
        cs = _score_maintenance(scan)
        assert cs.score >= 0
        assert cs.category == "maintenance"


# ── Badge URL Generation Tests ───────────────────────────────────────────


class TestGenerateBadgeUrl:
    """Tests for generate_badge_url."""

    def test_a_plus_grade(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=98.0,
            grade=Grade.A_PLUS,
        )
        url = generate_badge_url(result)
        assert "shields.io" in url
        assert "A%2B" in url or "A+" in url
        assert "brightgreen" in url

    def test_b_grade(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=75.0,
            grade=Grade.B,
        )
        url = generate_badge_url(result)
        assert "shields.io" in url
        assert "B" in url

    def test_f_grade(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=20.0,
            grade=Grade.F,
        )
        url = generate_badge_url(result)
        assert "shields.io" in url
        assert "F" in url
        assert "red" in url

    def test_url_format(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=92.0,
            grade=Grade.A,
        )
        url = generate_badge_url(result)
        assert url.startswith("https://img.shields.io/badge/")


# ── Markdown Report Generation Tests ─────────────────────────────────────


class TestGenerateMarkdownReport:
    """Tests for generate_markdown_report."""

    def test_basic_report(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=85.0,
            grade=Grade.A,
            category_scores=[
                CategoryScore(category="security", score=90.0, weight=0.3, weighted_score=27.0),
                CategoryScore(category="freshness", score=80.0, weight=0.2, weighted_score=16.0),
            ],
        )

        md = generate_markdown_report(result)
        assert "Scorecard" in md or "scorecard" in md.lower()
        assert "85" in md or "A" in md

    def test_with_suggestions(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=60.0,
            grade=Grade.C,
            category_scores=[],
            top_suggestions=["Update pkg-a to fix vulnerability"],
        )

        md = generate_markdown_report(result)
        assert "Update pkg-a" in md

    def test_perfect_score(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=100.0,
            grade=Grade.A_PLUS,
            category_scores=[
                CategoryScore(category="security", score=100.0, weight=0.3, weighted_score=30.0),
            ],
        )

        md = generate_markdown_report(result)
        assert "A+" in md


# ── Build Scorecard Tests (with mocking) ─────────────────────────────────


class TestBuildScorecard:
    """Tests for build_scorecard with mocked dependencies."""

    @patch("depcheck.scorecard.build_pin_report")
    @patch("depcheck.scorecard.build_size_report")
    @patch("depcheck.scorecard.scan_project")
    def test_basic_scorecard(
        self,
        mock_scan: MagicMock,
        mock_size: MagicMock,
        mock_pin: MagicMock,
    ) -> None:
        from depcheck.models import PackageReport, ScanResult
        from depcheck.depsize import SizeReport
        from depcheck.pinpoint import PinReport

        mock_scan.return_value = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="requests", installed_version="2.31.0"),
            ],
        )
        mock_size.return_value = SizeReport(project_path="/test")
        mock_pin.return_value = PinReport(
            project_path="/test", total_dependencies=1, pinned_count=1, health_score=100.0,
        )

        result = build_scorecard("/test", check_vulnerabilities=False)
        assert result.project_path == "/test"
        assert result.overall_score >= 0
        assert len(result.category_scores) > 0


# ── Rendering Tests ──────────────────────────────────────────────────────


class TestScorecardRendering:
    """Tests for scorecard rendering functions."""

    def test_render_scorecard_json(self) -> None:
        result = ScorecardResult(
            project_path="/test",
            overall_score=85.0,
            grade=Grade.A,
            category_scores=[
                CategoryScore(category="security", score=90.0, weight=0.3, weighted_score=27.0),
            ],
        )

        rendered = render_scorecard_json(result)
        parsed = json.loads(rendered)
        assert parsed["overall_score"] == 85.0
        assert parsed["grade"] == "A"

    def test_render_scorecard_table_no_crash(self) -> None:
        from rich.console import Console
        from io import StringIO

        result = ScorecardResult(
            project_path="/test",
            overall_score=75.0,
            grade=Grade.B,
            category_scores=[
                CategoryScore(
                    category="security",
                    score=80.0,
                    weight=0.3,
                    weighted_score=24.0,
                    details="2 vulnerabilities",
                ),
                CategoryScore(
                    category="freshness",
                    score=70.0,
                    weight=0.2,
                    weighted_score=14.0,
                    details="3 outdated packages",
                ),
            ],
            top_suggestions=["Update vulnerable package"],
        )

        console = Console(file=StringIO(), width=140)
        render_scorecard(result, console=console)

    def test_render_scorecard_perfect(self) -> None:
        from rich.console import Console
        from io import StringIO

        result = ScorecardResult(
            project_path="/test",
            overall_score=100.0,
            grade=Grade.A_PLUS,
            category_scores=[
                CategoryScore(
                    category="security",
                    score=100.0,
                    weight=0.3,
                    weighted_score=30.0,
                ),
            ],
        )

        console = Console(file=StringIO(), width=140)
        render_scorecard(result, console=console)

    def test_render_scorecard_failing(self) -> None:
        from rich.console import Console
        from io import StringIO

        result = ScorecardResult(
            project_path="/test",
            overall_score=25.0,
            grade=Grade.F,
            category_scores=[
                CategoryScore(
                    category="security",
                    score=20.0,
                    weight=0.3,
                    weighted_score=6.0,
                    details="5 critical vulnerabilities",
                ),
            ],
            top_suggestions=["Fix critical vulnerabilities immediately"],
        )

        console = Console(file=StringIO(), width=140)
        render_scorecard(result, console=console)
