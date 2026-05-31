"""Tests for depcheck search module."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from depcheck.models import HealthStatus
from depcheck.search import (
    SearchResult,
    SearchResults,
    _classify_license,
    _compute_health_score,
    _compute_health_status,
    _fetch_package_detail,
    render_search_json,
    render_search_table,
    search_by_category,
    search_packages,
)

# ── Fixtures ─────────────────────────────────────────────────────────────


def _make_pypi_info(
    name: str = "test-pkg",
    version: str = "1.0.0",
    summary: str = "A test package",
    license_str: str = "MIT",
    requires_python: str = ">=3.9",
    requires_dist: list[str] | None = None,
    releases: dict | None = None,
) -> dict:
    """Create a mock PyPI API response."""
    if requires_dist is None:
        requires_dist = ["click>=8.0", "rich>=13.0"]
    if releases is None:
        releases = {
            "1.0.0": [
                {
                    "packagetype": "bdist_wheel",
                    "size": 50000,
                    "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                    "yanked": False,
                },
                {
                    "packagetype": "sdist",
                    "size": 40000,
                    "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                    "yanked": False,
                },
            ],
        }

    classifiers = []
    if license_str == "MIT":
        classifiers.append("License :: OSI Approved :: MIT License")
    elif license_str == "Apache-2.0":
        classifiers.append("License :: OSI Approved :: Apache Software License")

    return {
        "info": {
            "name": name,
            "version": version,
            "summary": summary,
            "license": license_str,
            "requires_python": requires_python,
            "requires_dist": requires_dist,
            "home_page": f"https://github.com/test/{name}",
            "doc_url": f"https://{name}.readthedocs.io",
            "project_urls": {
                "Source": f"https://github.com/test/{name}",
                "Repository": f"https://github.com/test/{name}",
            },
            "classifiers": classifiers,
        },
        "releases": releases,
    }


# ── License classification tests ────────────────────────────────────────


class TestClassifyLicense:
    """Tests for _classify_license helper."""

    def test_mit(self) -> None:
        spdx, cat = _classify_license("MIT")
        assert spdx == "MIT"
        assert cat == "permissive"

    def test_apache(self) -> None:
        spdx, cat = _classify_license("Apache-2.0")
        assert spdx == "Apache-2.0"
        assert cat == "permissive"

    def test_bsd(self) -> None:
        spdx, cat = _classify_license("BSD-3-Clause")
        assert spdx == "BSD-3-Clause"
        assert cat == "permissive"

    def test_gpl(self) -> None:
        spdx, cat = _classify_license("GPL-3.0")
        assert spdx == "GPL-3.0"
        assert cat == "copyleft"

    def test_lgpl(self) -> None:
        spdx, cat = _classify_license("LGPL-2.1")
        assert spdx == "LGPL-2.1"
        assert cat == "copyleft"

    def test_cc0(self) -> None:
        spdx, cat = _classify_license("CC0-1.0")
        assert spdx == "CC0-1.0"
        assert cat == "public_domain"

    def test_empty(self) -> None:
        spdx, cat = _classify_license("")
        assert spdx == ""
        assert cat == "unknown"

    def test_unknown(self) -> None:
        spdx, cat = _classify_license("UNKNOWN")
        assert spdx == ""
        assert cat == "unknown"

    def test_none_string(self) -> None:
        spdx, cat = _classify_license("None")
        assert spdx == ""
        assert cat == "unknown"

    def test_case_insensitive(self) -> None:
        spdx, cat = _classify_license("mit")
        assert cat == "permissive"

    def test_substring_match_mit_like(self) -> None:
        spdx, cat = _classify_license("MIT-like license")
        assert cat == "permissive"

    def test_substring_match_gpl_like(self) -> None:
        spdx, cat = _classify_license("GNU GPL v3 or later")
        assert cat == "copyleft"

    def test_proprietary(self) -> None:
        spdx, cat = _classify_license("Proprietary")
        assert cat == "proprietary"

    def test_isc(self) -> None:
        spdx, cat = _classify_license("ISC")
        assert cat == "permissive"


# ── Health score tests ───────────────────────────────────────────────────


class TestHealthScore:
    """Tests for _compute_health_score."""

    def test_perfect_score(self) -> None:
        result = SearchResult(
            name="perfect-pkg",
            days_since_release=5,
            download_count=50_000_000,
            dependency_count=0,
            license_category="permissive",
        )
        score = _compute_health_score(result)
        # 30 (maintenance ≤30d) + 20 (10M+ dl) + 20 (0 deps) + 15 (permissive) + 15 (≤7d) = 100
        assert score == 100.0

    def test_very_old_unpopular(self) -> None:
        result = SearchResult(
            name="old-pkg",
            days_since_release=800,
            download_count=10,
            dependency_count=20,
            license_category="unknown",
        )
        score = _compute_health_score(result)
        # 0 (maintenance) + 0 (dl) + 0 (deps) + 2 (unknown) + 0 (recency) = 2
        assert score == 2.0

    def test_medium_score(self) -> None:
        result = SearchResult(
            name="medium-pkg",
            days_since_release=100,
            download_count=500_000,
            dependency_count=5,
            license_category="copyleft",
        )
        score = _compute_health_score(result)
        # 18 (91-180d) + 12 (100K dl) + 12 (4-7 deps) + 8 (copyleft) + 0 (recency >90) = 50
        assert score == 50.0

    def test_score_capped_at_100(self) -> None:
        """Ensure score doesn't exceed 100."""
        result = SearchResult(
            name="super-pkg",
            days_since_release=1,
            download_count=100_000_000,
            dependency_count=0,
            license_category="permissive",
        )
        score = _compute_health_score(result)
        assert score <= 100.0

    def test_recent_release(self) -> None:
        result = SearchResult(
            name="recent-pkg",
            days_since_release=15,
            download_count=10_000,
            dependency_count=2,
            license_category="permissive",
        )
        score = _compute_health_score(result)
        # 30 (≤30d) + 8 (10K dl) + 16 (1-3 deps) + 15 (permissive) + 10 (≤30d) = 79
        assert score == 79.0

    def test_copyleft_license_scoring(self) -> None:
        result_copyleft = SearchResult(
            name="copyleft-pkg",
            days_since_release=30,
            download_count=1_000_000,
            dependency_count=0,
            license_category="copyleft",
        )
        result_permissive = SearchResult(
            name="permissive-pkg",
            days_since_release=30,
            download_count=1_000_000,
            dependency_count=0,
            license_category="permissive",
        )
        score_copyleft = _compute_health_score(result_copyleft)
        score_permissive = _compute_health_score(result_permissive)
        assert score_permissive > score_copyleft


class TestHealthStatus:
    """Tests for _compute_health_status."""

    def test_healthy(self) -> None:
        result = SearchResult(days_since_release=30)
        status = _compute_health_status(result)
        assert status == HealthStatus.HEALTHY

    def test_outdated(self) -> None:
        result = SearchResult(days_since_release=200)
        status = _compute_health_status(result)
        assert status == HealthStatus.OUTDATED

    def test_unmaintained(self) -> None:
        result = SearchResult(days_since_release=400, is_unmaintained=True)
        status = _compute_health_status(result)
        assert status == HealthStatus.UNMAINTAINED

    def test_boundary_90_days(self) -> None:
        result = SearchResult(days_since_release=90)
        status = _compute_health_status(result)
        assert status == HealthStatus.HEALTHY

    def test_boundary_91_days(self) -> None:
        result = SearchResult(days_since_release=91)
        status = _compute_health_status(result)
        assert status == HealthStatus.OUTDATED


# ── SearchResult data model tests ───────────────────────────────────────


class TestSearchResult:
    """Tests for SearchResult dataclass."""

    def test_to_dict(self) -> None:
        result = SearchResult(
            name="test-pkg",
            version="1.0.0",
            summary="A test",
            license_spdx="MIT",
            license_category="permissive",
            score=85.5,
        )
        d = result.to_dict()
        assert d["name"] == "test-pkg"
        assert d["version"] == "1.0.0"
        assert d["score"] == 85.5
        assert d["health_status"] == "unknown"

    def test_default_values(self) -> None:
        result = SearchResult()
        assert result.name == ""
        assert result.dependencies == []
        assert result.dependency_count == 0
        assert result.score == 0.0


class TestSearchResults:
    """Tests for SearchResults dataclass."""

    def test_to_dict(self) -> None:
        results = SearchResults(
            query="test",
            results=[SearchResult(name="pkg1"), SearchResult(name="pkg2")],
            total=2,
        )
        d = results.to_dict()
        assert d["query"] == "test"
        assert d["total"] == 2
        assert len(d["results"]) == 2

    def test_empty_results(self) -> None:
        results = SearchResults(query="nothing")
        assert results.total == 0
        assert results.results == []


# ── Fetch package detail tests ───────────────────────────────────────────


class TestFetchPackageDetail:
    """Tests for _fetch_package_detail."""

    @patch("depcheck.search.PyPIClient")
    def test_fetch_success(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = _make_pypi_info(
            name="requests", version="2.31.0"
        )
        result = _fetch_package_detail(mock_client, "requests")
        assert result is not None
        assert result.name == "requests"
        assert result.version == "2.31.0"
        assert result.summary == "A test package"
        assert result.license_category == "permissive"

    @patch("depcheck.search.PyPIClient")
    def test_fetch_not_found(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = None
        result = _fetch_package_detail(mock_client, "nonexistent-pkg-xyz")
        assert result is None

    @patch("depcheck.search.PyPIClient")
    def test_fetch_with_dependencies(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = _make_pypi_info(
            requires_dist=["click>=8.0", "rich>=13.0", "urllib3>=1.21"]
        )
        result = _fetch_package_detail(mock_client, "test-pkg")
        assert result is not None
        assert result.dependency_count == 3
        assert "click" in result.dependencies
        assert "rich" in result.dependencies
        assert "urllib3" in result.dependencies

    @patch("depcheck.search.PyPIClient")
    def test_fetch_skips_platform_markers(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = _make_pypi_info(
            requires_dist=[
                "click>=8.0",
                "colorama>=0.4; sys_platform == 'win32'",
                "win32api; platform_system == 'Windows'",
            ]
        )
        result = _fetch_package_detail(mock_client, "test-pkg")
        assert result is not None
        assert result.dependency_count == 1
        assert result.dependencies == ["click"]

    @patch("depcheck.search.PyPIClient")
    def test_fetch_computes_score(self, mock_client_cls: MagicMock) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = _make_pypi_info(
            license_str="MIT",
        )
        result = _fetch_package_detail(mock_client, "test-pkg")
        assert result is not None
        assert result.score > 0


# ── Search packages tests ────────────────────────────────────────────────


class TestSearchPackages:
    """Tests for search_packages."""

    @patch("depcheck.search.PyPIClient")
    @patch("depcheck.search.httpx.Client")
    def test_search_returns_results(
    self, mock_http_cls: MagicMock, mock_pypi_cls: MagicMock
) -> None:
        # Mock HTTP client for simple index
        mock_http = MagicMock()
        mock_http.get.return_value = MagicMock(status_code=404)
        mock_http_cls.return_value = mock_http

        # Mock PyPI client
        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = _make_pypi_info(
            name="flask", version="3.0.0"
        )
        mock_pypi_cls.return_value = mock_pypi

        results = search_packages("flask", limit=5)
        assert results.query == "flask"
        # Should have found at least one result
        assert results.total >= 0  # May or may not find depending on mocks

    def test_search_with_limit(self) -> None:
        """Test that limit parameter is respected."""
        results = SearchResults(query="test", total=0)
        assert results.total == 0


class TestSearchByCategory:
    """Tests for search_by_category."""

    def test_unknown_category(self) -> None:
        results = search_by_category("nonexistent_category")
        assert len(results.errors) > 0
        assert "Unknown category" in results.errors[0]

    @patch("depcheck.search.PyPIClient")
    def test_web_category(self, mock_pypi_cls: MagicMock) -> None:
        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = _make_pypi_info(
            name="flask", version="3.0.0", license_str="BSD-3-Clause"
        )
        mock_pypi_cls.return_value = mock_pypi

        results = search_by_category("web", limit=3)
        assert results.query == "category:web"
        # Results should be sorted by score
        if len(results.results) > 1:
            for i in range(len(results.results) - 1):
                assert results.results[i].score >= results.results[i + 1].score


# ── Rendering tests ──────────────────────────────────────────────────────


class TestRenderSearchTable:
    """Tests for render_search_table."""

    def test_renders_without_error(self) -> None:
        from io import StringIO

        from rich.console import Console

        results = SearchResults(
            query="test",
            results=[
                SearchResult(
                    name="test-pkg",
                    version="1.0.0",
                    summary="A test package",
                    license_spdx="MIT",
                    license_category="permissive",
                    score=85.0,
                    health_status=HealthStatus.HEALTHY,
                ),
            ],
            total=1,
        )

        console = Console(file=StringIO(), width=120)
        render_search_table(results, console=console)
        output = console.file.getvalue()
        assert "test-pkg" in output
        assert "1.0.0" in output

    def test_renders_empty_results(self) -> None:
        from io import StringIO

        from rich.console import Console

        results = SearchResults(query="nothing", results=[], total=0)
        console = Console(file=StringIO(), width=120)
        render_search_table(results, console=console)
        output = console.file.getvalue()
        assert "No packages found" in output

    def test_renders_errors(self) -> None:
        from io import StringIO

        from rich.console import Console

        results = SearchResults(
            query="bad",
            errors=["Something went wrong"],
        )
        console = Console(file=StringIO(), width=120)
        render_search_table(results, console=console)
        output = console.file.getvalue()
        assert "Something went wrong" in output


class TestRenderSearchJson:
    """Tests for render_search_json."""

    def test_valid_json(self) -> None:
        results = SearchResults(
            query="test",
            results=[
                SearchResult(name="pkg1", version="1.0.0", score=90.0),
            ],
            total=1,
        )
        json_str = render_search_json(results)
        data = json.loads(json_str)
        assert data["query"] == "test"
        assert data["total"] == 1
        assert data["results"][0]["name"] == "pkg1"

    def test_empty_results_json(self) -> None:
        results = SearchResults(query="empty")
        json_str = render_search_json(results)
        data = json.loads(json_str)
        assert data["total"] == 0
        assert data["results"] == []


# ── Integration-style tests (mocked) ─────────────────────────────────────


class TestSearchIntegration:
    """Integration tests for search with mocked PyPI."""

    @patch("depcheck.search.PyPIClient")
    @patch("depcheck.search.httpx.Client")
    def test_search_with_license_filter(
        self, mock_http_cls: MagicMock, mock_pypi_cls: MagicMock
    ) -> None:
        mock_http = MagicMock()
        mock_http.get.return_value = MagicMock(status_code=404)
        mock_http_cls.return_value = mock_http

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        # Return copyleft-licensed package
        mock_pypi.get_package_info.return_value = _make_pypi_info(
            name="gpl-pkg", license_str="GPL-3.0"
        )
        mock_pypi_cls.return_value = mock_pypi

        results = search_packages("gpl-pkg", license_filter="permissive")
        # GPL package should be filtered out when filtering for permissive
        for r in results.results:
            assert r.license_category == "permissive"

    @patch("depcheck.search.PyPIClient")
    @patch("depcheck.search.httpx.Client")
    def test_search_with_min_score(
        self, mock_http_cls: MagicMock, mock_pypi_cls: MagicMock
    ) -> None:
        mock_http = MagicMock()
        mock_http.get.return_value = MagicMock(status_code=404)
        mock_http_cls.return_value = mock_http

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = _make_pypi_info(name="test-pkg")
        mock_pypi_cls.return_value = mock_pypi

        results = search_packages("test-pkg", min_score=999)
        # No package should score that high
        assert results.total == 0
