"""Tests for depcheck.depsize — dependency size estimation and reporting."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from depcheck.depsize import (
    BLOAT_THRESHOLD_MB,
    INSTALL_SIZE_MULTIPLIER,
    LARGE_PACKAGE_THRESHOLD_MB,
    PackageSize,
    SizeReport,
    _format_size,
    _get_package_download_size,
    build_size_report,
    render_size_bar_chart,
    render_size_json,
    render_size_table,
)

# ── PackageSize Tests ────────────────────────────────────────────────────


class TestPackageSize:
    """Tests for the PackageSize dataclass."""

    def test_defaults(self) -> None:
        ps = PackageSize(name="test-pkg")
        assert ps.name == "test-pkg"
        assert ps.version is None
        assert ps.download_size_bytes == 0
        assert ps.install_size_bytes == 0
        assert ps.file_type == "unknown"
        assert ps.is_large is False
        assert ps.is_bloated is False
        assert ps.error is None

    def test_download_size_mb(self) -> None:
        ps = PackageSize(name="big-pkg", download_size_bytes=5 * 1024 * 1024)
        assert ps.download_size_mb == pytest.approx(5.0)

    def test_install_size_mb(self) -> None:
        ps = PackageSize(name="big-pkg", install_size_bytes=int(12.5 * 1024 * 1024))
        assert ps.install_size_mb == pytest.approx(12.5)

    def test_to_dict(self) -> None:
        ps = PackageSize(
            name="requests",
            version="2.31.0",
            download_size_bytes=200000,
            install_size_bytes=500000,
            file_type="wheel",
            is_large=False,
            is_bloated=False,
        )
        d = ps.to_dict()
        assert d["name"] == "requests"
        assert d["version"] == "2.31.0"
        assert d["download_size_mb"] == pytest.approx(0.19, abs=0.01)
        assert d["file_type"] == "wheel"

    def test_error_package(self) -> None:
        ps = PackageSize(name="missing", error="Package not found on PyPI")
        d = ps.to_dict()
        assert d["error"] == "Package not found on PyPI"


# ── SizeReport Tests ─────────────────────────────────────────────────────


class TestSizeReport:
    """Tests for the SizeReport dataclass."""

    def test_defaults(self) -> None:
        report = SizeReport(project_path="/test")
        assert report.project_path == "/test"
        assert report.packages == []
        assert report.total_download_bytes == 0
        assert report.total_install_bytes == 0
        assert report.large_packages == []
        assert report.bloated_packages == []
        assert report.errors == []

    def test_total_download_mb(self) -> None:
        report = SizeReport(project_path="/test", total_download_bytes=10 * 1024 * 1024)
        assert report.total_download_mb == pytest.approx(10.0)

    def test_total_install_mb(self) -> None:
        report = SizeReport(project_path="/test", total_install_bytes=25 * 1024 * 1024)
        assert report.total_install_mb == pytest.approx(25.0)

    def test_packages_with_sizes(self) -> None:
        report = SizeReport(project_path="/test")
        report.packages = [
            PackageSize(name="a", download_size_bytes=100),
            PackageSize(name="b", error="not found"),
            PackageSize(name="c", download_size_bytes=200),
        ]
        assert report.packages_with_sizes == 2
        assert report.packages_with_errors == 1

    def test_to_dict(self) -> None:
        report = SizeReport(
            project_path="/test",
            total_download_bytes=1000,
            total_install_bytes=2500,
        )
        report.packages = [PackageSize(name="a", download_size_bytes=1000, install_size_bytes=2500)]
        d = report.to_dict()
        assert d["project_path"] == "/test"
        assert d["summary"]["total_download_mb"] == pytest.approx(0.0, abs=0.01)
        assert len(d["packages"]) == 1


# ── Helper Function Tests ────────────────────────────────────────────────


class TestFormatSize:
    """Tests for _format_size."""

    def test_bytes(self) -> None:
        assert _format_size(500) == "500 B"

    def test_kilobytes(self) -> None:
        assert _format_size(1536) == "1.5 KB"

    def test_megabytes(self) -> None:
        assert _format_size(2 * 1024 * 1024) == "2.0 MB"

    def test_large_megabytes(self) -> None:
        assert _format_size(150 * 1024 * 1024) == "150.0 MB"

    def test_zero(self) -> None:
        assert _format_size(0) == "0 B"


# ── Package Size Fetching Tests (with mocking) ───────────────────────────


class TestGetPackageDownloadSize:
    """Tests for _get_package_download_size."""

    def test_package_not_found(self) -> None:
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = None
        result = _get_package_download_size("nonexistent", pypi=mock_pypi)
        assert result.error is not None
        assert "not found" in result.error.lower()

    def test_no_releases(self) -> None:
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = {
            "info": {"version": "1.0"},
            "releases": {},
        }
        result = _get_package_download_size("no-releases", pypi=mock_pypi)
        assert result.error is not None

    def test_wheel_preferred(self) -> None:
        """Test that wheel files are preferred over sdist."""
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "filename": "pkg-1.0.0-py3-none-any.whl",
                        "size": 50000,
                        "yanked": False,
                    },
                    {
                        "packagetype": "sdist",
                        "filename": "pkg-1.0.0.tar.gz",
                        "size": 120000,
                        "yanked": False,
                    },
                ],
            },
        }

        result = _get_package_download_size("pkg", version="1.0.0", pypi=mock_pypi)
        assert result.error is None
        assert result.file_type == "wheel"
        assert result.download_size_bytes == 50000

    def test_sdist_fallback(self) -> None:
        """Test fallback to sdist when no wheel available."""
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "packagetype": "sdist",
                        "filename": "pkg-1.0.0.tar.gz",
                        "size": 120000,
                        "yanked": False,
                    },
                ],
            },
        }

        result = _get_package_download_size("pkg", version="1.0.0", pypi=mock_pypi)
        assert result.error is None
        assert result.file_type == "sdist"
        assert result.download_size_bytes == 120000

    def test_install_size_multiplier(self) -> None:
        """Test that install size is download size * multiplier."""
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "filename": "pkg-1.0.0-py3-none-any.whl",
                        "size": 100000,
                        "yanked": False,
                    },
                ],
            },
        }

        result = _get_package_download_size("pkg", version="1.0.0", pypi=mock_pypi)
        assert result.install_size_bytes == int(100000 * INSTALL_SIZE_MULTIPLIER)

    def test_large_package_flag(self) -> None:
        """Test that large packages are flagged correctly."""
        large_bytes = int(LARGE_PACKAGE_THRESHOLD_MB * 1024 * 1024) + 1
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "filename": "big-pkg-1.0.0.whl",
                        "size": large_bytes,
                        "yanked": False,
                    },
                ],
            },
        }

        result = _get_package_download_size("big-pkg", version="1.0.0", pypi=mock_pypi)
        assert result.is_large is True
        assert result.is_bloated is False

    def test_bloated_package_flag(self) -> None:
        """Test that bloated packages are flagged correctly."""
        bloated_bytes = int(BLOAT_THRESHOLD_MB * 1024 * 1024) + 1
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "filename": "huge-pkg-1.0.0.whl",
                        "size": bloated_bytes,
                        "yanked": False,
                    },
                ],
            },
        }

        result = _get_package_download_size("huge-pkg", version="1.0.0", pypi=mock_pypi)
        assert result.is_bloated is True
        assert result.is_large is True

    def test_pure_wheel_preferred(self) -> None:
        """Test that pure-python wheels (none-any) are preferred."""
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = {
            "info": {"version": "1.0.0"},
            "releases": {
                "1.0.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "filename": "pkg-1.0.0-cp311-linux_x86_64.whl",
                        "size": 200000,
                        "yanked": False,
                    },
                    {
                        "packagetype": "bdist_wheel",
                        "filename": "pkg-1.0.0-py3-none-any.whl",
                        "size": 50000,
                        "yanked": False,
                    },
                ],
            },
        }

        result = _get_package_download_size("pkg", version="1.0.0", pypi=mock_pypi)
        assert result.download_size_bytes == 50000
        assert result.file_type == "wheel"


# ── Build Size Report Tests ──────────────────────────────────────────────


class TestBuildSizeReport:
    """Tests for build_size_report with mocked scanner."""

    @patch("depcheck.depsize.scan_project")
    @patch("depcheck.depsize.PyPIClient")
    def test_build_report(self, mock_pypi_cls: MagicMock, mock_scan: MagicMock) -> None:
        """Test building a size report."""
        from depcheck.models import PackageReport, ScanResult

        mock_scan.return_value = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="requests", installed_version="2.31.0"),
            ],
        )

        mock_client = MagicMock()
        mock_pypi_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_pypi_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.get_package_info.return_value = {
            "info": {"version": "2.31.0"},
            "releases": {
                "2.31.0": [
                    {
                        "packagetype": "bdist_wheel",
                        "filename": "requests-2.31.0-py3-none-any.whl",
                        "size": 60000,
                        "yanked": False,
                    },
                ],
            },
        }

        report = build_size_report("/test")
        assert len(report.packages) == 1
        assert report.packages[0].name == "requests"

    @patch("depcheck.depsize.scan_project")
    @patch("depcheck.depsize.PyPIClient")
    def test_totals_calculation(self, mock_pypi_cls: MagicMock, mock_scan: MagicMock) -> None:
        """Test that totals are calculated correctly."""
        from depcheck.models import PackageReport, ScanResult

        mock_scan.return_value = ScanResult(
            project_path="/test",
            packages=[
                PackageReport(name="a", installed_version="1.0"),
                PackageReport(name="b", installed_version="2.0"),
            ],
        )

        mock_client = MagicMock()
        mock_pypi_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_pypi_cls.return_value.__exit__ = MagicMock(return_value=False)

        def mock_info(name: str) -> dict:
            return {
                "info": {"version": "1.0"},
                "releases": {
                    "1.0": [
                        {
                            "packagetype": "bdist_wheel",
                            "filename": f"{name}-1.0.whl",
                            "size": 10000,
                            "yanked": False,
                        },
                    ],
                    "2.0": [
                        {
                            "packagetype": "bdist_wheel",
                            "filename": f"{name}-2.0.whl",
                            "size": 20000,
                            "yanked": False,
                        },
                    ],
                },
            }

        mock_client.get_package_info.side_effect = mock_info

        report = build_size_report("/test")
        assert report.total_download_bytes > 0
        assert report.total_install_bytes > 0


# ── Rendering Tests ──────────────────────────────────────────────────────


class TestSizeRendering:
    """Tests for size report rendering functions."""

    def test_render_size_json(self) -> None:
        report = SizeReport(
            project_path="/test", total_download_bytes=1000, total_install_bytes=2500
        )
        report.packages = [PackageSize(name="a", download_size_bytes=1000, install_size_bytes=2500)]

        result = render_size_json(report)
        parsed = json.loads(result)
        assert parsed["project_path"] == "/test"

    def test_render_size_table_no_crash(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(
            project_path="/test", total_download_bytes=5000, total_install_bytes=12500
        )
        report.packages = [
            PackageSize(
                name="a",
                version="1.0",
                download_size_bytes=5000,
                install_size_bytes=12500,
                file_type="wheel",
            ),
        ]

        console = Console(file=StringIO(), width=120)
        render_size_table(report, console=console)

    def test_render_size_bar_chart_no_crash(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(project_path="/test")
        report.packages = [
            PackageSize(name="big-pkg", download_size_bytes=5 * 1024 * 1024, is_large=True),
            PackageSize(name="small-pkg", download_size_bytes=50000),
        ]

        console = Console(file=StringIO(), width=120)
        render_size_bar_chart(report, console=console)

    def test_render_size_bar_chart_empty(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(project_path="/test")
        console = Console(file=StringIO(), width=120)
        render_size_bar_chart(report, console=console)


# ── Constants Tests ──────────────────────────────────────────────────────


class TestConstants:
    """Tests for module constants."""

    def test_install_multiplier(self) -> None:
        assert INSTALL_SIZE_MULTIPLIER == 2.5

    def test_thresholds(self) -> None:
        assert LARGE_PACKAGE_THRESHOLD_MB == 10.0
        assert BLOAT_THRESHOLD_MB == 50.0
        assert BLOAT_THRESHOLD_MB > LARGE_PACKAGE_THRESHOLD_MB
