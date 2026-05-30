"""Tests for the bundle module — dependency bundle size analysis and optimization."""

from __future__ import annotations

import json
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from depcheck.bundle import (
    BundleResult,
    OptimizationRecommendation,
    OptimizationType,
    PackageSizeInfo,
    RedundancyGroup,
    SizeCategory,
    _classify_size,
    _count_dependencies_from_info,
    _detect_c_extensions,
    _extract_extras,
    _get_wheel_size,
    _human_readable_size,
    analyze_package_size,
    detect_redundancies,
    generate_recommendations,
    render_bundle_json,
    render_bundle_table,
    run_bundle,
)
from depcheck.models import ParsedDependency


# ---------------------------------------------------------------------------
# Unit tests for _human_readable_size
# ---------------------------------------------------------------------------


class TestHumanReadableSize:
    """Tests for _human_readable_size."""

    def test_bytes(self) -> None:
        assert _human_readable_size(500) == "500 B"

    def test_kilobytes(self) -> None:
        result = _human_readable_size(1024 * 100)
        assert "KB" in result

    def test_megabytes(self) -> None:
        result = _human_readable_size(1024 * 1024 * 5)
        assert "MB" in result

    def test_gigabytes(self) -> None:
        result = _human_readable_size(1024 * 1024 * 1024 * 2)
        assert "GB" in result

    def test_none(self) -> None:
        assert _human_readable_size(None) == "unknown"

    def test_zero(self) -> None:
        assert _human_readable_size(0) == "0 B"

    def test_exact_kb(self) -> None:
        assert _human_readable_size(1024) == "1.0 KB"

    def test_exact_mb(self) -> None:
        assert _human_readable_size(1024 * 1024) == "1.0 MB"


# ---------------------------------------------------------------------------
# Unit tests for _classify_size
# ---------------------------------------------------------------------------


class TestClassifySize:
    """Tests for _classify_size."""

    def test_tiny(self) -> None:
        assert _classify_size(500) == SizeCategory.TINY

    def test_small(self) -> None:
        assert _classify_size(500 * 1024) == SizeCategory.SMALL

    def test_medium(self) -> None:
        assert _classify_size(5 * 1024 * 1024) == SizeCategory.MEDIUM

    def test_large(self) -> None:
        assert _classify_size(30 * 1024 * 1024) == SizeCategory.LARGE

    def test_very_large(self) -> None:
        assert _classify_size(100 * 1024 * 1024) == SizeCategory.VERY_LARGE

    def test_huge(self) -> None:
        assert _classify_size(300 * 1024 * 1024) == SizeCategory.HUGE

    def test_none(self) -> None:
        assert _classify_size(None) == SizeCategory.TINY

    def test_boundary_values(self) -> None:
        assert _classify_size(99 * 1024) == SizeCategory.TINY
        assert _classify_size(100 * 1024) == SizeCategory.SMALL
        assert _classify_size(999 * 1024) == SizeCategory.SMALL
        assert _classify_size(1024 * 1024) == SizeCategory.MEDIUM


# ---------------------------------------------------------------------------
# Unit tests for _detect_c_extensions
# ---------------------------------------------------------------------------


class TestDetectCExtensions:
    """Tests for _detect_c_extensions."""

    def test_pure_python_wheel(self) -> None:
        info = {
            "info": {"version": "1.0.0", "classifiers": []},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                    }
                ]
            },
        }
        assert _detect_c_extensions(info, "1.0.0") is False

    def test_c_extension_wheel(self) -> None:
        info = {
            "info": {"version": "1.0.0", "classifiers": []},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0-cp311-cp311-manylinux_2_17_x86_64.whl",
                        "packagetype": "bdist_wheel",
                    }
                ]
            },
        }
        assert _detect_c_extensions(info, "1.0.0") is True

    def test_classifier_c(self) -> None:
        info = {
            "info": {
                "version": "1.0.0",
                "classifiers": ["Programming Language :: C"],
            },
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                    }
                ]
            },
        }
        assert _detect_c_extensions(info, "1.0.0") is True

    def test_classifier_rust(self) -> None:
        info = {
            "info": {
                "version": "1.0.0",
                "classifiers": ["Programming Language :: Rust"],
            },
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0.tar.gz",
                        "packagetype": "sdist",
                    }
                ]
            },
        }
        assert _detect_c_extensions(info, "1.0.0") is True

    def test_no_version(self) -> None:
        info = {
            "info": {"version": "1.0.0", "classifiers": []},
            "releases": {},
        }
        assert _detect_c_extensions(info, None) is False


# ---------------------------------------------------------------------------
# Unit tests for _count_dependencies_from_info
# ---------------------------------------------------------------------------


class TestCountDependencies:
    """Tests for _count_dependencies_from_info."""

    def test_no_requires_dist(self) -> None:
        info = {"info": {}}
        assert _count_dependencies_from_info(info) == 0

    def test_with_dependencies(self) -> None:
        info = {
            "info": {
                "requires_dist": [
                    "requests>=2.0",
                    "click>=8.0",
                    "rich>=13.0",
                ]
            }
        }
        assert _count_dependencies_from_info(info) == 3

    def test_excluding_extras(self) -> None:
        info = {
            "info": {
                "requires_dist": [
                    "requests>=2.0",
                    "pytest ; extra == 'dev'",
                    "black ; extra == 'lint'",
                ]
            }
        }
        assert _count_dependencies_from_info(info) == 1

    def test_none_requires_dist(self) -> None:
        info = {"info": {"requires_dist": None}}
        assert _count_dependencies_from_info(info) == 0

    def test_empty_strings(self) -> None:
        info = {
            "info": {
                "requires_dist": ["", "  ", "requests>=2.0"]
            }
        }
        assert _count_dependencies_from_info(info) == 1


# ---------------------------------------------------------------------------
# Unit tests for _extract_extras
# ---------------------------------------------------------------------------


class TestExtractExtras:
    """Tests for _extract_extras."""

    def test_no_extras(self) -> None:
        info = {"info": {"requires_dist": ["requests>=2.0"]}}
        assert _extract_extras(info) == []

    def test_with_extras(self) -> None:
        info = {
            "info": {
                "requires_dist": [
                    "requests>=2.0",
                    'pytest ; extra == "dev"',
                    'black ; extra == "lint"',
                    'sphinx ; extra == "docs"',
                ]
            }
        }
        extras = _extract_extras(info)
        assert "dev" in extras
        assert "lint" in extras
        assert "docs" in extras

    def test_single_quotes(self) -> None:
        info = {
            "info": {
                "requires_dist": [
                    "pytest ; extra == 'test'",
                ]
            }
        }
        extras = _extract_extras(info)
        assert "test" in extras

    def test_no_requires_dist(self) -> None:
        info = {"info": {}}
        assert _extract_extras(info) == []


# ---------------------------------------------------------------------------
# Unit tests for _get_wheel_size
# ---------------------------------------------------------------------------


class TestGetWheelSize:
    """Tests for _get_wheel_size."""

    def test_universal_wheel(self) -> None:
        info = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "size": 50000,
                    }
                ]
            },
        }
        assert _get_wheel_size(info, "1.0.0") == 50000

    def test_platform_wheel(self) -> None:
        info = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0-cp311-cp311-linux_x86_64.whl",
                        "packagetype": "bdist_wheel",
                        "size": 200000,
                    }
                ]
            },
        }
        assert _get_wheel_size(info, "1.0.0") == 200000

    def test_sdist_fallback(self) -> None:
        info = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0.tar.gz",
                        "packagetype": "sdist",
                        "size": 100000,
                    }
                ]
            },
        }
        assert _get_wheel_size(info, "1.0.0") == 100000

    def test_no_releases_for_version(self) -> None:
        info = {
            "info": {"version": "1.0.0"},
            "releases": {
                "0.9.0": [
                    {
                        "filename": "test-0.9.0.tar.gz",
                        "packagetype": "sdist",
                        "size": 100000,
                    }
                ]
            },
        }
        assert _get_wheel_size(info, "1.0.0") is None

    def test_no_size_in_file(self) -> None:
        info = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                    }
                ]
            },
        }
        assert _get_wheel_size(info, "1.0.0") is None


# ---------------------------------------------------------------------------
# Unit tests for analyze_package_size
# ---------------------------------------------------------------------------


class TestAnalyzePackageSize:
    """Tests for analyze_package_size."""

    def test_none_info(self) -> None:
        dep = ParsedDependency(name="test-pkg", version="1.0.0")
        info = analyze_package_size(dep, None)
        assert info.package_name == "test-pkg"
        assert info.wheel_size_bytes is None
        assert info.wheel_size_human == "unknown"

    def test_with_info(self) -> None:
        dep = ParsedDependency(name="test-pkg", version="1.0.0")
        pypi_info = {
            "info": {
                "version": "1.0.0",
                "classifiers": [],
                "requires_dist": ["click>=8.0", "rich>=13.0"],
            },
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "size": 500000,
                        "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                        "yanked": False,
                    }
                ]
            },
        }
        info = analyze_package_size(dep, pypi_info)
        assert info.package_name == "test-pkg"
        assert info.wheel_size_bytes == 500000
        assert info.size_category == SizeCategory.SMALL  # 488 KB is small
        assert info.dependency_count == 2

    def test_with_extras(self) -> None:
        dep = ParsedDependency(name="test-pkg", version="1.0.0")
        pypi_info = {
            "info": {
                "version": "1.0.0",
                "classifiers": [],
                "requires_dist": [
                    "click>=8.0",
                    'pytest ; extra == "dev"',
                    'sphinx ; extra == "docs"',
                ],
            },
            "releases": {
                "1.0.0": [
                    {
                        "filename": "test-1.0.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "size": 50000,
                        "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                        "yanked": False,
                    }
                ]
            },
        }
        info = analyze_package_size(dep, pypi_info)
        assert "dev" in info.extras
        assert "docs" in info.extras


# ---------------------------------------------------------------------------
# Unit tests for detect_redundancies
# ---------------------------------------------------------------------------


class TestDetectRedundancies:
    """Tests for detect_redundancies."""

    def test_no_redundancies(self) -> None:
        groups = detect_redundancies(["click", "rich", "httpx"])
        assert len(groups) == 0

    def test_http_client_redundancy(self) -> None:
        groups = detect_redundancies(["requests", "httpx"])
        assert len(groups) >= 1
        http_groups = [g for g in groups if g.group_name == "HTTP Clients"]
        assert len(http_groups) == 1
        assert "requests" in http_groups[0].packages_found
        assert "httpx" in http_groups[0].packages_found

    def test_linting_redundancy(self) -> None:
        groups = detect_redundancies(["ruff", "flake8"])
        lint_groups = [g for g in groups if g.group_name == "Linting"]
        assert len(lint_groups) == 1

    def test_no_group_with_single_package(self) -> None:
        groups = detect_redundancies(["requests", "click"])
        # requests is in HTTP group alone, click is in CLI group alone
        # Should not trigger redundancy
        assert all(len(g.packages_found) >= 2 for g in groups)


# ---------------------------------------------------------------------------
# Unit tests for generate_recommendations
# ---------------------------------------------------------------------------


class TestGenerateRecommendations:
    """Tests for generate_recommendations."""

    def test_recommendation_for_large_package(self) -> None:
        packages = [
            PackageSizeInfo(
                package_name="pandas",
                version="2.0.0",
                wheel_size_bytes=50 * 1024 * 1024,
                size_category=SizeCategory.LARGE,
            )
        ]
        recs = generate_recommendations(packages, [])
        assert len(recs) >= 1
        replace_recs = [r for r in recs if r.optimization_type == OptimizationType.REPLACE]
        assert len(replace_recs) >= 1
        assert any("polars" in r.description for r in replace_recs)

    def test_recommendation_for_redundancy(self) -> None:
        packages = [
            PackageSizeInfo(package_name="requests", version="2.31.0"),
            PackageSizeInfo(package_name="httpx", version="0.25.0"),
        ]
        redundancy_groups = [
            RedundancyGroup(
                group_name="HTTP Clients",
                packages_found=["requests", "httpx"],
                message="Multiple HTTP clients found",
            )
        ]
        recs = generate_recommendations(packages, redundancy_groups)
        consolidate = [r for r in recs if r.optimization_type == OptimizationType.CONSOLIDATE]
        assert len(consolidate) >= 1

    def test_recommendations_sorted_by_priority(self) -> None:
        packages = [
            PackageSizeInfo(
                package_name="pandas",
                version="2.0.0",
                wheel_size_bytes=50 * 1024 * 1024,
                size_category=SizeCategory.LARGE,
            ),
            PackageSizeInfo(
                package_name="requests",
                version="2.31.0",
                wheel_size_bytes=200 * 1024,
                size_category=SizeCategory.SMALL,
            ),
        ]
        recs = generate_recommendations(packages, [])
        # High priority should come before medium/low
        priorities = [r.priority for r in recs]
        high_indices = [i for i, p in enumerate(priorities) if p == "high"]
        low_indices = [i for i, p in enumerate(priorities) if p == "low"]
        if high_indices and low_indices:
            assert min(high_indices) < max(low_indices)


# ---------------------------------------------------------------------------
# Unit tests for serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    """Tests for to_dict serialization."""

    def test_package_size_info_to_dict(self) -> None:
        psi = PackageSizeInfo(
            package_name="test",
            version="1.0.0",
            wheel_size_bytes=50000,
            wheel_size_human="48.8 KB",
            size_category=SizeCategory.SMALL,
            dependency_count=3,
        )
        d = psi.to_dict()
        assert d["package_name"] == "test"
        assert d["wheel_size_bytes"] == 50000
        assert d["size_category"] == "small"

    def test_redundancy_group_to_dict(self) -> None:
        rg = RedundancyGroup(
            group_name="HTTP Clients",
            packages_found=["requests", "httpx"],
            message="Multiple HTTP clients",
        )
        d = rg.to_dict()
        assert d["group_name"] == "HTTP Clients"
        assert len(d["packages_found"]) == 2

    def test_optimization_recommendation_to_dict(self) -> None:
        rec = OptimizationRecommendation(
            optimization_type=OptimizationType.REPLACE,
            package_name="pandas",
            description="Consider polars",
            estimated_savings="~50%",
            priority="high",
        )
        d = rec.to_dict()
        assert d["optimization_type"] == "replace"
        assert d["estimated_savings"] == "~50%"

    def test_bundle_result_to_dict(self) -> None:
        result = BundleResult(
            project_path="/test",
            total_size_bytes=1000000,
            total_size_human="976.6 KB",
            packages=[
                PackageSizeInfo(package_name="test", wheel_size_bytes=500000),
            ],
            size_by_category={"small": 1},
        )
        d = result.to_dict()
        assert d["total_size_bytes"] == 1000000
        assert len(d["packages"]) == 1

    def test_json_roundtrip(self) -> None:
        result = BundleResult(
            project_path="/test",
            total_size_bytes=100000,
            total_size_human="97.7 KB",
            packages=[
                PackageSizeInfo(
                    package_name="pkg-a",
                    version="1.0.0",
                    wheel_size_bytes=50000,
                    size_category=SizeCategory.SMALL,
                ),
            ],
            recommendations=[
                OptimizationRecommendation(
                    optimization_type=OptimizationType.CONSOLIDATE,
                    package_name="a, b",
                    description="Consolidate",
                ),
            ],
        )
        data = json.dumps(result.to_dict())
        parsed = json.loads(data)
        assert parsed["total_size_bytes"] == 100000
        assert len(parsed["recommendations"]) == 1


# ---------------------------------------------------------------------------
# Unit tests for rendering
# ---------------------------------------------------------------------------


class TestRendering:
    """Tests for render functions."""

    def test_render_bundle_table(self) -> None:
        result = BundleResult(
            project_path="/test",
            total_size_bytes=500000,
            total_size_human="488.3 KB",
            packages=[
                PackageSizeInfo(
                    package_name="pkg-a",
                    version="1.0.0",
                    wheel_size_bytes=300000,
                    wheel_size_human="293.0 KB",
                    size_category=SizeCategory.MEDIUM,
                    dependency_count=2,
                ),
                PackageSizeInfo(
                    package_name="pkg-b",
                    version="2.0.0",
                    wheel_size_bytes=200000,
                    wheel_size_human="195.3 KB",
                    size_category=SizeCategory.SMALL,
                    dependency_count=0,
                    extras=["dev"],
                ),
            ],
            size_by_category={"small": 1, "medium": 1},
            top_heavy_packages=[
                PackageSizeInfo(
                    package_name="pkg-a",
                    wheel_size_bytes=300000,
                    wheel_size_human="293.0 KB",
                    size_category=SizeCategory.MEDIUM,
                ),
            ],
            redundancy_groups=[
                RedundancyGroup(
                    group_name="HTTP Clients",
                    packages_found=["requests", "httpx"],
                    message="Multiple HTTP clients",
                )
            ],
            recommendations=[
                OptimizationRecommendation(
                    optimization_type=OptimizationType.CONSOLIDATE,
                    package_name="requests, httpx",
                    description="Multiple HTTP clients found",
                    priority="medium",
                ),
            ],
        )
        # Just verify it doesn't crash
        render_bundle_table(result)

    def test_render_bundle_json(self) -> None:
        result = BundleResult(
            project_path="/test",
            total_size_bytes=50000,
            total_size_human="48.8 KB",
            packages=[
                PackageSizeInfo(package_name="test", wheel_size_bytes=50000),
            ],
        )
        from rich.console import Console

        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_bundle_json(result, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert data["total_size_bytes"] == 50000


# ---------------------------------------------------------------------------
# Integration test for run_bundle with mocked PyPI
# ---------------------------------------------------------------------------


class TestRunBundleMocked:
    """Tests for run_bundle with mocked dependencies."""

    def test_with_mocked_scanner(self) -> None:
        """Test run_bundle with mocked discover_dependencies and PyPIClient."""
        import tempfile

        mock_deps = [
            ParsedDependency(name="click", version="8.1.0"),
            ParsedDependency(name="rich", version="13.0.0"),
        ]

        mock_pypi_info = {
            "info": {
                "version": "8.1.0",
                "classifiers": [],
                "requires_dist": [],
            },
            "releases": {
                "8.1.0": [
                    {
                        "filename": "click-8.1.0-py3-none-any.whl",
                        "packagetype": "bdist_wheel",
                        "size": 100000,
                        "upload_time_iso_8601": "2024-01-15T10:00:00Z",
                        "yanked": False,
                    }
                ]
            },
        }

        with tempfile.TemporaryDirectory() as tmpdir, \
             patch("depcheck.bundle.discover_dependencies") as mock_discover, \
             patch("depcheck.bundle.PyPIClient") as mock_pypi_class:
            mock_discover.return_value = (mock_deps, ["pyproject.toml"])
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.get_package_info.return_value = mock_pypi_info
            mock_pypi_class.return_value = mock_client

            result = run_bundle(tmpdir)
            assert len(result.packages) == 2
