"""Tests for depcheck size module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from depcheck.models import HealthStatus
from depcheck.size import (
    PackageSize,
    SizeReport,
    _categorize_size,
    _human_size,
    _fetch_package_size,
    analyze_project_sizes,
    compare_package_sizes,
    render_comparison_json,
    render_size_comparison,
    render_size_json,
    render_size_table,
)


# ── Human size tests ─────────────────────────────────────────────────────


class TestHumanSize:
    """Tests for _human_size helper."""

    def test_zero(self) -> None:
        assert _human_size(0) == "0 KB"

    def test_bytes(self) -> None:
        assert _human_size(0.5) == "512 B"

    def test_kilobytes(self) -> None:
        assert _human_size(500) == "500.0 KB"

    def test_megabytes(self) -> None:
        # 5000 KB = 5.0 MB
        assert _human_size(5000) == "5.0 MB"

    def test_large_megabytes(self) -> None:
        # 50000 KB is in the very_large range: 50000/10000 = 5.0 MB
        # (Note: the code divides by VERY_LARGE_PKG_THRESHOLD_KB for this range)
        assert _human_size(50_000) == "5.0 MB"

    def test_very_large_megabytes(self) -> None:
        # 100000 KB / 10000 = 10.0 MB (uses VERY_LARGE scale)
        assert _human_size(100_000) == "10.0 MB"

    def test_negative_returns_zero(self) -> None:
        assert _human_size(-1) == "0 KB"

    def test_just_under_1mb(self) -> None:
        assert _human_size(999) == "999.0 KB"

    def test_exactly_1mb(self) -> None:
        # 1000 KB = 1.0 MB
        assert _human_size(1000) == "1.0 MB"

    def test_10mb(self) -> None:
        # 10000 KB is in the very_large range: 10000/10000 = 1.0 MB
        # (Note: >= VERY_LARGE_PKG_THRESHOLD_KB uses /10000 division)
        assert _human_size(10_000) == "1.0 MB"

    def test_one_kb(self) -> None:
        assert _human_size(1) == "1.0 KB"


class TestCategorizeSize:
    """Tests for _categorize_size helper."""

    def test_tiny(self) -> None:
        assert _categorize_size(10) == "tiny"

    def test_small(self) -> None:
        assert _categorize_size(500) == "small"

    def test_medium(self) -> None:
        assert _categorize_size(5000) == "medium"

    def test_large(self) -> None:
        assert _categorize_size(50_000) == "large"

    def test_very_large(self) -> None:
        assert _categorize_size(200_000) == "very_large"

    def test_zero(self) -> None:
        assert _categorize_size(0) == "unknown"

    def test_negative(self) -> None:
        assert _categorize_size(-1) == "unknown"

    def test_boundary_tiny(self) -> None:
        assert _categorize_size(49) == "tiny"

    def test_boundary_small(self) -> None:
        assert _categorize_size(50) == "small"

    def test_boundary_medium(self) -> None:
        assert _categorize_size(1000) == "medium"

    def test_boundary_large(self) -> None:
        assert _categorize_size(10_000) == "large"

    def test_boundary_very_large(self) -> None:
        assert _categorize_size(100_000) == "very_large"


# ── PackageSize data model tests ────────────────────────────────────────


class TestPackageSize:
    """Tests for PackageSize dataclass."""

    def test_download_size_prefers_wheel(self) -> None:
        pkg = PackageSize(wheel_size_kb=100, source_size_kb=200)
        assert pkg.download_size_kb == 100

    def test_download_size_falls_back_to_source(self) -> None:
        pkg = PackageSize(wheel_size_kb=0.0, source_size_kb=200)
        assert pkg.download_size_kb == 200

    def test_download_size_zero(self) -> None:
        pkg = PackageSize()
        assert pkg.download_size_kb == 0.0

    def test_human_download_size(self) -> None:
        pkg = PackageSize(wheel_size_kb=5000)
        assert pkg.human_download_size == "5.0 MB"

    def test_human_install_size(self) -> None:
        pkg = PackageSize(wheel_size_kb=1000, estimated_install_kb=2500)
        assert pkg.human_install_size == "2.5 MB"

    def test_to_dict(self) -> None:
        pkg = PackageSize(
            name="test-pkg",
            version="1.0.0",
            wheel_size_kb=500,
            source_size_kb=400,
            estimated_install_kb=1250,
            category="small",
            has_wheel=True,
            has_sdist=True,
        )
        d = pkg.to_dict()
        assert d["name"] == "test-pkg"
        assert d["version"] == "1.0.0"
        assert d["wheel_size_kb"] == 500
        assert d["category"] == "small"
        assert d["has_wheel"] is True
        assert d["has_sdist"] is True

    def test_defaults(self) -> None:
        pkg = PackageSize()
        assert pkg.name == ""
        assert pkg.alternatives == []
        assert pkg.file_count == 0
        assert pkg.wheel_size_kb == 0.0
        assert pkg.source_size_kb == 0.0

    def test_status_default(self) -> None:
        pkg = PackageSize()
        assert pkg.status == HealthStatus.UNKNOWN


# ── SizeReport data model tests ──────────────────────────────────────────


class TestSizeReport:
    """Tests for SizeReport dataclass."""

    def test_human_total_download(self) -> None:
        # 10000 KB is in very_large range: 10000/10000 = 1.0 MB
        report = SizeReport(total_download_kb=10_000)
        assert report.human_total_download == "1.0 MB"

    def test_human_total_install(self) -> None:
        # 25000 KB is in very_large range: 25000/10000 = 2.5 MB
        report = SizeReport(total_install_kb=25_000)
        assert report.human_total_install == "2.5 MB"

    def test_to_dict(self) -> None:
        report = SizeReport(
            project_path="/tmp/test",
            total_download_kb=5000,
            total_install_kb=12500,
            total_file_count=100,
            category_breakdown={"small": 3, "medium": 1},
        )
        d = report.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert d["total_download_kb"] == 5000
        assert d["total_file_count"] == 100
        assert d["category_breakdown"]["small"] == 3

    def test_empty_report(self) -> None:
        report = SizeReport()
        assert report.human_total_download == "0 KB"
        assert report.packages == []
        assert report.errors == []


# ── Fetch package size tests ─────────────────────────────────────────────


class TestFetchPackageSize:
    """Tests for _fetch_package_size."""

    def _make_pypi_info(self, name: str = "test-pkg", version: str = "1.0.0") -> dict:
        return {
            "info": {
                "name": name,
                "version": version,
                "license": "MIT",
            },
            "releases": {
                "1.0.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "size": 100_000,  # ~97.7 KB
                        "upload_time_iso_8601": "2024-06-15T10:00:00Z",
                        "yanked": False,
                    },
                    {
                        "packagetype": "sdist",
                        "size": 80_000,  # ~78.1 KB
                        "upload_time_iso_8601": "2024-06-15T10:00:00Z",
                        "yanked": False,
                    },
                ],
            },
        }

    def test_fetch_success(self) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = self._make_pypi_info()

        result = _fetch_package_size(mock_client, "test-pkg")
        assert result.name == "test-pkg"
        assert result.version == "1.0.0"
        assert result.has_wheel is True
        assert result.has_sdist is True
        assert result.wheel_size_kb > 0
        assert result.source_size_kb > 0
        assert result.estimated_install_kb > 0
        assert result.status == HealthStatus.HEALTHY

    def test_fetch_not_found(self) -> None:
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = None

        result = _fetch_package_size(mock_client, "nonexistent")
        assert result.name == "nonexistent"
        assert result.status == HealthStatus.REMOVED

    def test_fetch_wheel_only(self) -> None:
        info = {
            "info": {"name": "wheel-only", "version": "2.0.0", "license": "MIT"},
            "releases": {
                "2.0.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "size": 200_000,
                        "upload_time_iso_8601": "2024-06-15T10:00:00Z",
                        "yanked": False,
                    },
                ],
            },
        }
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = info

        result = _fetch_package_size(mock_client, "wheel-only")
        assert result.has_wheel is True
        assert result.has_sdist is False
        assert result.wheel_size_kb > 0
        assert result.source_size_kb == 0

    def test_fetch_suggests_alternatives_for_large(self) -> None:
        info = {
            "info": {"name": "requests", "version": "2.31.0", "license": "Apache-2.0"},
            "releases": {
                "2.31.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "size": 2_000_000,  # ~1953 KB > 1000 threshold
                        "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                        "yanked": False,
                    },
                ],
            },
        }
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = info

        result = _fetch_package_size(mock_client, "requests")
        assert result.alternatives  # Should suggest alternatives
        assert "httpx" in result.alternatives

    def test_fetch_no_alternatives_for_small(self) -> None:
        info = {
            "info": {"name": "tiny-pkg", "version": "0.1.0", "license": "MIT"},
            "releases": {
                "0.1.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "size": 10_000,  # ~9.8 KB — tiny
                        "upload_time_iso_8601": "2024-06-15T10:00:00Z",
                        "yanked": False,
                    },
                ],
            },
        }
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = info

        result = _fetch_package_size(mock_client, "tiny-pkg")
        assert result.alternatives == []
        assert result.category == "tiny"

    def test_fetch_estimates_install_size(self) -> None:
        info = {
            "info": {"name": "mid-pkg", "version": "1.0.0", "license": "MIT"},
            "releases": {
                "1.0.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "size": 500_000,  # ~488 KB
                        "upload_time_iso_8601": "2024-06-15T10:00:00Z",
                        "yanked": False,
                    },
                ],
            },
        }
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = info

        result = _fetch_package_size(mock_client, "mid-pkg")
        # Install size should be ~2.5x download size
        expected_install = result.download_size_kb * 2.5
        assert abs(result.estimated_install_kb - expected_install) < 0.1

    def test_fetch_no_releases(self) -> None:
        info = {
            "info": {"name": "no-releases", "version": "0.0.0", "license": "MIT"},
            "releases": {},
        }
        mock_client = MagicMock()
        mock_client.get_package_info.return_value = info

        result = _fetch_package_size(mock_client, "no-releases")
        assert result.name == "no-releases"
        assert result.version == "0.0.0"
        assert result.wheel_size_kb == 0.0
        assert result.has_wheel is False


# ── Analyze project sizes tests ──────────────────────────────────────────


class TestAnalyzeProjectSizes:
    """Tests for analyze_project_sizes."""

    def test_invalid_path(self) -> None:
        report = analyze_project_sizes("/nonexistent/path/xyz")
        assert len(report.errors) > 0

    def test_no_dependencies(self, tmp_path: Path) -> None:
        report = analyze_project_sizes(str(tmp_path))
        assert len(report.errors) > 0
        assert any("No dependencies" in e for e in report.errors)

    @patch("depcheck.size._fetch_package_size")
    @patch("depcheck.size.discover_dependencies")
    def test_with_dependencies(
        self, mock_discover: MagicMock, mock_fetch: MagicMock, tmp_path: Path
    ) -> None:
        from depcheck.models import ParsedDependency

        mock_discover.return_value = (
            [
                ParsedDependency(name="flask", version="3.0.0"),
                ParsedDependency(name="click", version="8.1.0"),
            ],
            ["pyproject.toml"],
        )
        mock_fetch.side_effect = [
            PackageSize(name="flask", version="3.0.0", wheel_size_kb=500, estimated_install_kb=1250, category="small"),
            PackageSize(name="click", version="8.1.0", wheel_size_kb=200, estimated_install_kb=500, category="tiny"),
        ]

        report = analyze_project_sizes(str(tmp_path))
        assert len(report.packages) == 2
        assert report.total_download_kb == 700
        assert report.total_install_kb == 1750

    @patch("depcheck.size._fetch_package_size")
    @patch("depcheck.size.discover_dependencies")
    def test_category_breakdown(
        self, mock_discover: MagicMock, mock_fetch: MagicMock, tmp_path: Path
    ) -> None:
        from depcheck.models import ParsedDependency

        mock_discover.return_value = (
            [ParsedDependency(name="a"), ParsedDependency(name="b"), ParsedDependency(name="c")],
            ["pyproject.toml"],
        )
        mock_fetch.side_effect = [
            PackageSize(name="a", wheel_size_kb=10, estimated_install_kb=25, category="tiny"),
            PackageSize(name="b", wheel_size_kb=500, estimated_install_kb=1250, category="small"),
            PackageSize(name="c", wheel_size_kb=5000, estimated_install_kb=12500, category="medium"),
        ]

        report = analyze_project_sizes(str(tmp_path))
        assert report.category_breakdown.get("tiny") == 1
        assert report.category_breakdown.get("small") == 1
        assert report.category_breakdown.get("medium") == 1

    @patch("depcheck.size._fetch_package_size")
    @patch("depcheck.size.discover_dependencies")
    def test_largest_packages(
        self, mock_discover: MagicMock, mock_fetch: MagicMock, tmp_path: Path
    ) -> None:
        from depcheck.models import ParsedDependency

        mock_discover.return_value = (
            [ParsedDependency(name="small"), ParsedDependency(name="big")],
            ["pyproject.toml"],
        )
        mock_fetch.side_effect = [
            PackageSize(name="small", wheel_size_kb=100, estimated_install_kb=250, category="small"),
            PackageSize(name="big", wheel_size_kb=50000, estimated_install_kb=125000, category="large"),
        ]

        report = analyze_project_sizes(str(tmp_path))
        assert report.largest_packages[0] == "big"

    @patch("depcheck.size._fetch_package_size")
    @patch("depcheck.size.discover_dependencies")
    def test_error_handling_for_fetch(
        self, mock_discover: MagicMock, mock_fetch: MagicMock, tmp_path: Path
    ) -> None:
        from depcheck.models import ParsedDependency

        mock_discover.return_value = (
            [ParsedDependency(name="good"), ParsedDependency(name="bad")],
            ["pyproject.toml"],
        )

        def fetch_side_effect(client, name, version=None):
            if name == "bad":
                raise RuntimeError("API error")
            return PackageSize(name="good", wheel_size_kb=100, category="tiny")

        mock_fetch.side_effect = fetch_side_effect

        report = analyze_project_sizes(str(tmp_path))
        # Should have error for bad package and still include good
        assert any("bad" in e for e in report.errors)
        assert len(report.packages) == 2


# ── Compare package sizes tests ──────────────────────────────────────────


class TestComparePackageSizes:
    """Tests for compare_package_sizes."""

    @patch("depcheck.size._fetch_package_size")
    def test_compare_sorts_by_size(self, mock_fetch: MagicMock) -> None:
        mock_fetch.side_effect = [
            PackageSize(name="big", wheel_size_kb=5000, category="medium"),
            PackageSize(name="tiny", wheel_size_kb=50, category="tiny"),
            PackageSize(name="mid", wheel_size_kb=500, category="small"),
        ]

        results = compare_package_sizes(["big", "tiny", "mid"])
        assert len(results) == 3
        assert results[0].name == "tiny"
        assert results[1].name == "mid"
        assert results[2].name == "big"

    @patch("depcheck.size._fetch_package_size")
    def test_compare_handles_errors(self, mock_fetch: MagicMock) -> None:
        def fetch_side_effect(client, name, version=None):
            if name == "bad":
                raise Exception("API error")
            return PackageSize(name="good", wheel_size_kb=100)

        mock_fetch.side_effect = fetch_side_effect

        results = compare_package_sizes(["good", "bad"])
        assert len(results) == 2
        # Error packages have download_size_kb=0, so they sort first
        assert results[0].name == "bad"
        assert results[0].status == HealthStatus.UNKNOWN
        assert results[1].name == "good"

    @patch("depcheck.size._fetch_package_size")
    def test_compare_empty_list(self, mock_fetch: MagicMock) -> None:
        results = compare_package_sizes([])
        assert results == []
        mock_fetch.assert_not_called()


# ── Rendering tests ──────────────────────────────────────────────────────


class TestRenderSizeTable:
    """Tests for render_size_table."""

    def test_renders_report(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(
            project_path="/tmp/test",
            packages=[
                PackageSize(
                    name="test-pkg",
                    version="1.0.0",
                    wheel_size_kb=5000,
                    estimated_install_kb=12500,
                    category="medium",
                    has_wheel=True,
                ),
            ],
            total_download_kb=5000,
            total_install_kb=12500,
            category_breakdown={"medium": 1},
            largest_packages=["test-pkg"],
        )

        console = Console(file=StringIO(), width=120)
        render_size_table(report, console=console)

    def test_renders_errors_only(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(errors=["Something went wrong"])
        console = Console(file=StringIO(), width=120)
        render_size_table(report, console=console)

    def test_renders_empty_packages(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(project_path="/tmp/test")
        console = Console(file=StringIO(), width=120)
        render_size_table(report, console=console)


class TestRenderSizeJson:
    """Tests for render_size_json."""

    def test_valid_json(self) -> None:
        report = SizeReport(
            project_path="/tmp/test",
            total_download_kb=1000,
        )
        json_str = render_size_json(report)
        data = json.loads(json_str)
        assert data["project_path"] == "/tmp/test"
        assert data["total_download_kb"] == 1000

    def test_includes_packages(self) -> None:
        report = SizeReport(
            packages=[
                PackageSize(name="pkg1", wheel_size_kb=100),
            ]
        )
        json_str = render_size_json(report)
        data = json.loads(json_str)
        assert len(data["packages"]) == 1


class TestRenderComparisonJson:
    """Tests for render_comparison_json."""

    def test_valid_json(self) -> None:
        packages = [
            PackageSize(name="pkg1", wheel_size_kb=100),
            PackageSize(name="pkg2", wheel_size_kb=500),
        ]
        json_str = render_comparison_json(packages)
        data = json.loads(json_str)
        assert len(data) == 2
        assert data[0]["name"] == "pkg1"


class TestRenderSizeComparison:
    """Tests for render_size_comparison."""

    def test_renders_comparison(self) -> None:
        from io import StringIO

        from rich.console import Console

        packages = [
            PackageSize(name="small", wheel_size_kb=100, category="tiny", has_wheel=True),
            PackageSize(name="big", wheel_size_kb=5000, category="medium", has_wheel=True),
        ]

        console = Console(file=StringIO(), width=120)
        render_size_comparison(packages, console=console)

    def test_empty_comparison(self) -> None:
        from io import StringIO

        from rich.console import Console

        console = Console(file=StringIO(), width=120)
        render_size_comparison([], console=console)

    def test_single_package(self) -> None:
        from io import StringIO

        from rich.console import Console

        packages = [PackageSize(name="only", wheel_size_kb=500, category="small", has_wheel=True)]
        console = Console(file=StringIO(), width=120)
        render_size_comparison(packages, console=console)
