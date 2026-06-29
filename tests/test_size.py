"""Tests for depcheck.size — dependency size/footprint analysis."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from depcheck.size import (
    PackageSize,
    SizeReport,
    _human_size,
    analyze_sizes,
    find_site_packages,
    measure_package_size,
    render_size_json,
    render_size_table,
    resolve_package_dir,
    resolve_package_version,
)

# ---------------------------------------------------------------------------
# PackageSize unit tests
# ---------------------------------------------------------------------------


class TestPackageSize:
    """Tests for the PackageSize dataclass."""

    def test_total_kb(self) -> None:
        pkg = PackageSize(name="foo", version="1.0", total_bytes=2048)
        assert pkg.total_kb == 2.0

    def test_total_mb(self) -> None:
        pkg = PackageSize(name="foo", version="1.0", total_bytes=1048576)
        assert pkg.total_mb == 1.0

    def test_human_size_bytes(self) -> None:
        pkg = PackageSize(name="foo", version="1.0", total_bytes=512)
        assert pkg.human_size() == "512 B"

    def test_human_size_kb(self) -> None:
        pkg = PackageSize(name="foo", version="1.0", total_bytes=2048)
        assert pkg.human_size() == "2.0 KB"

    def test_human_size_mb(self) -> None:
        pkg = PackageSize(name="foo", version="1.0", total_bytes=5 * 1024 * 1024)
        assert pkg.human_size() == "5.0 MB"

    def test_human_size_gb(self) -> None:
        pkg = PackageSize(name="foo", version="1.0", total_bytes=2 * 1024 * 1024 * 1024)
        assert pkg.human_size() == "2.0 GB"

    def test_to_dict(self) -> None:
        pkg = PackageSize(
            name="foo",
            version="1.0",
            total_bytes=1024,
            file_count=5,
            dir_count=2,
            top_files=[("bar.py", 500)],
            install_path="/lib/foo",
        )
        d = pkg.to_dict()
        assert d["name"] == "foo"
        assert d["total_bytes"] == 1024
        assert d["total_kb"] == 1.0
        assert d["file_count"] == 5
        assert d["dir_count"] == 2
        assert len(d["top_files"]) == 1

    def test_to_dict_with_error(self) -> None:
        pkg = PackageSize(name="foo", version="1.0", error="not installed")
        d = pkg.to_dict()
        assert d["error"] == "not installed"
        assert d["total_bytes"] == 0


# ---------------------------------------------------------------------------
# SizeReport unit tests
# ---------------------------------------------------------------------------


class TestSizeReport:
    """Tests for the SizeReport dataclass."""

    def _make_report(self) -> SizeReport:
        pkgs = [
            PackageSize(name="a", version="1.0", total_bytes=100, file_count=2, dir_count=1),
            PackageSize(name="b", version="2.0", total_bytes=300, file_count=5, dir_count=2),
            PackageSize(name="c", version="3.0", total_bytes=200, file_count=3, dir_count=1),
        ]
        return SizeReport(project_path="/tmp/test", packages=pkgs)

    def test_total_bytes(self) -> None:
        report = self._make_report()
        assert report.total_bytes == 600

    def test_total_file_count(self) -> None:
        report = self._make_report()
        assert report.total_file_count == 10

    def test_total_dir_count(self) -> None:
        report = self._make_report()
        assert report.total_dir_count == 4

    def test_total_kb(self) -> None:
        report = self._make_report()
        assert report.total_kb == pytest.approx(600 / 1024)

    def test_total_mb(self) -> None:
        report = self._make_report()
        assert report.total_mb == pytest.approx(600 / (1024 * 1024))

    def test_package_count(self) -> None:
        report = self._make_report()
        assert report.package_count == 3

    def test_largest(self) -> None:
        report = self._make_report()
        assert report.largest is not None
        assert report.largest.name == "b"

    def test_smallest(self) -> None:
        report = self._make_report()
        assert report.smallest is not None
        assert report.smallest.name == "a"

    def test_median_bytes_odd(self) -> None:
        report = self._make_report()  # 100, 200, 300
        assert report.median_bytes == 200.0

    def test_median_bytes_even(self) -> None:
        pkgs = [
            PackageSize(name="a", version="1.0", total_bytes=100),
            PackageSize(name="b", version="2.0", total_bytes=200),
            PackageSize(name="c", version="3.0", total_bytes=300),
            PackageSize(name="d", version="4.0", total_bytes=400),
        ]
        report = SizeReport(project_path="/tmp", packages=pkgs)
        assert report.median_bytes == 250.0

    def test_median_bytes_empty(self) -> None:
        report = SizeReport(project_path="/tmp")
        assert report.median_bytes == 0.0

    def test_top_n(self) -> None:
        report = self._make_report()
        top2 = report.top_n(2)
        assert len(top2) == 2
        assert top2[0].name == "b"
        assert top2[1].name == "c"

    def test_bottom_n(self) -> None:
        report = self._make_report()
        bot2 = report.bottom_n(2)
        assert len(bot2) == 2
        assert bot2[0].name == "a"
        assert bot2[1].name == "c"

    def test_largest_empty(self) -> None:
        report = SizeReport(project_path="/tmp")
        assert report.largest is None

    def test_smallest_empty(self) -> None:
        report = SizeReport(project_path="/tmp")
        assert report.smallest is None

    def test_to_dict(self) -> None:
        report = self._make_report()
        d = report.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert d["summary"]["total_bytes"] == 600
        assert d["summary"]["package_count"] == 3
        assert len(d["packages"]) == 3
        # Packages sorted by size descending
        assert d["packages"][0]["name"] == "b"


# ---------------------------------------------------------------------------
# Site-packages discovery tests
# ---------------------------------------------------------------------------


class TestFindSitePackages:
    """Tests for find_site_packages."""

    def test_finds_site_packages(self) -> None:
        """find_site_packages should return a Path or None."""
        result = find_site_packages()
        if result is not None:
            assert isinstance(result, Path)
            assert result.is_dir()

    def test_result_name(self) -> None:
        """If found, the result should be named site-packages or dist-packages."""
        result = find_site_packages()
        if result is not None:
            assert result.name in ("site-packages", "dist-packages")


# ---------------------------------------------------------------------------
# Package resolution tests
# ---------------------------------------------------------------------------


class TestResolvePackageDir:
    """Tests for resolve_package_dir."""

    def test_finds_installed_package(self, tmp_path: Path) -> None:
        site = tmp_path / "site-packages"
        site.mkdir()
        pkg_dir = site / "requests"
        pkg_dir.mkdir()

        result = resolve_package_dir("requests", site)
        assert result is not None
        assert result.name == "requests"

    def test_normalizes_hyphens(self, tmp_path: Path) -> None:
        site = tmp_path / "site-packages"
        site.mkdir()
        # Package installed with underscores
        pkg_dir = site / "my_package"
        pkg_dir.mkdir()

        result = resolve_package_dir("my-package", site)
        assert result is not None

    def test_returns_none_for_missing(self, tmp_path: Path) -> None:
        site = tmp_path / "site-packages"
        site.mkdir()

        result = resolve_package_dir("nonexistent-pkg", site)
        assert result is None


class TestResolvePackageVersion:
    """Tests for resolve_package_version."""

    def test_reads_from_dist_info(self, tmp_path: Path) -> None:
        site = tmp_path / "site-packages"
        site.mkdir()
        dist_info = site / "requests-2.31.0.dist-info"
        dist_info.mkdir()

        result = resolve_package_version("requests", site)
        assert result == "2.31.0"

    def test_returns_unknown_for_missing(self, tmp_path: Path) -> None:
        site = tmp_path / "site-packages"
        site.mkdir()

        result = resolve_package_version("nonexistent", site)
        assert result == "unknown"


# ---------------------------------------------------------------------------
# measure_package_size tests
# ---------------------------------------------------------------------------


class TestMeasurePackageSize:
    """Tests for measure_package_size."""

    def test_measures_directory(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / "mypkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("# init")
        (pkg_dir / "module.py").write_text("x = 1")

        total, files, dirs, top = measure_package_size(pkg_dir)
        assert total > 0
        assert files == 2
        assert dirs == 0
        assert len(top) <= 5

    def test_measures_nested_dirs(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / "mypkg"
        pkg_dir.mkdir()
        sub = pkg_dir / "sub"
        sub.mkdir()
        (sub / "deep.py").write_text("y = 2")

        total, files, dirs, top = measure_package_size(pkg_dir)
        assert total > 0
        assert files == 1
        assert dirs == 1

    def test_empty_directory(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / "empty"
        pkg_dir.mkdir()

        total, files, dirs, top = measure_package_size(pkg_dir)
        assert total == 0
        assert files == 0
        assert dirs == 0
        assert top == []

    def test_top_files_sorted_by_size(self, tmp_path: Path) -> None:
        pkg_dir = tmp_path / "mypkg"
        pkg_dir.mkdir()
        (pkg_dir / "small.py").write_text("x")
        (pkg_dir / "large.py").write_text("x" * 1000)
        (pkg_dir / "medium.py").write_text("x" * 100)

        total, files, dirs, top = measure_package_size(pkg_dir)
        assert len(top) == 3
        assert top[0][1] >= top[1][1] >= top[2][1]


# ---------------------------------------------------------------------------
# analyze_sizes integration tests
# ---------------------------------------------------------------------------


class TestAnalyzeSizes:
    """Integration tests for analyze_sizes."""

    def test_invalid_path(self) -> None:
        report = analyze_sizes("/nonexistent/path")
        assert len(report.errors) > 0

    def test_no_dependencies(self, tmp_path: Path) -> None:
        # Empty project with no dependency files
        report = analyze_sizes(str(tmp_path))
        assert len(report.errors) > 0 or report.package_count == 0

    def test_with_requirements(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("click==8.0\nrequests==2.31.0\n")

        with patch("depcheck.size.find_site_packages", return_value=None):
            report = analyze_sizes(str(tmp_path))
            # When site_packages is None, we get an error
            # but the dependencies should have been discovered
            assert report.package_count == 0  # error path returns early
            assert len(report.errors) > 0

    def test_with_mocked_site_packages(self, tmp_path: Path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("mypkg==1.0\n")

        site = tmp_path / "site-packages"
        site.mkdir()
        pkg_dir = site / "mypkg"
        pkg_dir.mkdir()
        (pkg_dir / "__init__.py").write_text("x = 1")
        dist_info = site / "mypkg-1.0.dist-info"
        dist_info.mkdir()

        with (
            patch("depcheck.size.find_site_packages", return_value=site),
            patch("depcheck.size.resolve_package_dir", return_value=pkg_dir),
            patch("depcheck.size.resolve_package_version", return_value="1.0"),
        ):
            report = analyze_sizes(str(tmp_path))
            assert report.package_count == 1
            pkg = report.packages[0]
            assert pkg.name == "mypkg"
            assert pkg.total_bytes > 0
            assert pkg.file_count == 1


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


class TestHumanSize:
    """Tests for the _human_size helper."""

    def test_bytes(self) -> None:
        assert _human_size(512) == "512 B"

    def test_kb(self) -> None:
        assert _human_size(2048) == "2.0 KB"

    def test_mb(self) -> None:
        assert _human_size(5 * 1024 * 1024) == "5.0 MB"

    def test_gb(self) -> None:
        assert _human_size(3 * 1024 * 1024 * 1024) == "3.0 GB"


class TestRenderSizeTable:
    """Tests for render_size_table."""

    def test_renders_without_error(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(
            project_path="/tmp/test",
            packages=[
                PackageSize(name="a", version="1.0", total_bytes=100, file_count=2),
            ],
        )
        console = Console(file=StringIO(), width=120)
        render_size_table(report, console=console)
        # Should not raise

    def test_renders_empty_report(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(project_path="/tmp/test")
        console = Console(file=StringIO(), width=120)
        render_size_table(report, console=console)


class TestRenderSizeJson:
    """Tests for render_size_json."""

    def test_produces_valid_json(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = SizeReport(
            project_path="/tmp/test",
            packages=[
                PackageSize(name="a", version="1.0", total_bytes=100, file_count=2),
            ],
        )
        buf = StringIO()
        console = Console(file=buf, width=1000, force_terminal=False, no_color=True)
        render_size_json(report, console=console)
        data = json.loads(buf.getvalue())
        assert "summary" in data
        assert "packages" in data
