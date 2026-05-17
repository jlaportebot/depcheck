"""Tests for depcheck scanner module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from depcheck.models import HealthStatus, PackageReport, ScanResult, Vulnerability
from depcheck.scanner import (
    _parse_pep621_dependency,
    discover_dependencies,
    normalize_package_name,
    parse_pipfile,
    parse_pyproject_toml,
    parse_requirements_txt,
)


class TestNormalizePackageName:
    """Tests for package name normalization."""

    def test_lowercase(self) -> None:
        assert normalize_package_name("Requests") == "requests"

    def test_underscores_to_hyphens(self) -> None:
        assert normalize_package_name("my_package") == "my-package"

    def test_dots_to_hyphens(self) -> None:
        assert normalize_package_name("zope.interface") == "zope-interface"

    def test_multiple_separators(self) -> None:
        assert normalize_package_name("my__package") == "my-package"

    def test_already_normalized(self) -> None:
        assert normalize_package_name("requests") == "requests"


class TestParseRequirementsTxt:
    """Tests for requirements.txt parsing."""

    def test_simple_package(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests\n")
            f.flush()
            deps = parse_requirements_txt(Path(f.name))
            assert len(deps) == 1
            assert deps[0].name == "requests"
            assert deps[0].version is None

    def test_pinned_version(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests==2.31.0\n")
            f.flush()
            deps = parse_requirements_txt(Path(f.name))
            assert len(deps) == 1
            assert deps[0].name == "requests"
            assert deps[0].version == "2.31.0"

    def test_version_specifier(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("requests>=2.28\n")
            f.flush()
            deps = parse_requirements_txt(Path(f.name))
            assert len(deps) == 1
            assert deps[0].name == "requests"

    def test_comments_and_blanks(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("# This is a comment\n\nrequests==2.31.0\n# Another comment\nflask\n")
            f.flush()
            deps = parse_requirements_txt(Path(f.name))
            assert len(deps) == 2

    def test_pip_options_skipped(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write(
                "-i https://pypi.org/simple\n--index-url https://example.com\nrequests==2.31.0\n"
            )
            f.flush()
            deps = parse_requirements_txt(Path(f.name))
            assert len(deps) == 1

    def test_nonexistent_file(self) -> None:
        deps = parse_requirements_txt(Path("/nonexistent/requirements.txt"))
        assert deps == []


class TestParsePyprojectToml:
    """Tests for pyproject.toml parsing."""

    def test_pep621_dependencies(self) -> None:
        content = """
[project]
name = "myproject"
dependencies = [
    "requests>=2.28",
    "flask==2.3.0",
]
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            deps = parse_pyproject_toml(Path(f.name))
            assert len(deps) == 2
            names = [d.name for d in deps]
            assert "requests" in names
            assert "flask" in names

    def test_poetry_dependencies(self) -> None:
        content = """
[tool.poetry.dependencies]
python = "^3.9"
requests = "^2.28"
flask = "2.3.0"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".toml", delete=False) as f:
            f.write(content)
            f.flush()
            deps = parse_pyproject_toml(Path(f.name))
            # Python should be excluded
            names = [d.name for d in deps]
            assert "python" not in names
            assert "requests" in names
            assert "flask" in names

    def test_nonexistent_file(self) -> None:
        deps = parse_pyproject_toml(Path("/nonexistent/pyproject.toml"))
        assert deps == []


class TestParsePipfile:
    """Tests for Pipfile parsing."""

    def test_simple_packages(self) -> None:
        content = """
[packages]
requests = "==2.31.0"
flask = "*"
click = ">=8.0"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix="", delete=False, dir="/tmp") as f:
            f.write(content)
            f.flush()
            deps = parse_pipfile(Path(f.name))
            assert len(deps) == 3

    def test_nonexistent_file(self) -> None:
        deps = parse_pipfile(Path("/nonexistent/Pipfile"))
        assert deps == []


class TestParsePep621Dependency:
    """Tests for PEP 621 dependency string parsing."""

    def test_simple_name(self) -> None:
        dep = _parse_pep621_dependency("requests")
        assert dep is not None
        assert dep.name == "requests"
        assert dep.version is None

    def test_pinned_version(self) -> None:
        dep = _parse_pep621_dependency("requests==2.31.0")
        assert dep is not None
        assert dep.name == "requests"
        assert dep.version == "2.31.0"

    def test_with_extras(self) -> None:
        dep = _parse_pep621_dependency("requests[security]>=2.28")
        assert dep is not None
        assert dep.name == "requests"

    def test_invalid_input(self) -> None:
        dep = _parse_pep621_dependency("")
        assert dep is None


class TestDiscoverDependencies:
    """Tests for dependency discovery."""

    def test_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            deps, files = discover_dependencies(Path(tmpdir))
            assert deps == []
            assert files == []

    def test_with_requirements_txt(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "requirements.txt"
            req_path.write_text("requests==2.31.0\nflask==2.3.0\n")
            deps, files = discover_dependencies(Path(tmpdir))
            assert len(deps) == 2
            assert len(files) == 1

    def test_deduplication(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "requirements.txt"
            req_path.write_text("requests==2.31.0\nrequests==2.30.0\n")
            deps, files = discover_dependencies(Path(tmpdir))
            assert len(deps) == 1


class TestModels:
    """Tests for data models."""

    def test_vulnerability_to_dict(self) -> None:
        vuln = Vulnerability(
            vuln_id="CVE-2023-1234",
            summary="Test vulnerability",
            severity="HIGH",
            url="https://osv.dev/vulnerability/CVE-2023-1234",
            aliases=["GHSA-xxxx"],
        )
        d = vuln.to_dict()
        assert d["id"] == "CVE-2023-1234"
        assert d["severity"] == "HIGH"
        assert "GHSA-xxxx" in d["aliases"]

    def test_package_report_is_outdated(self) -> None:
        report = PackageReport(
            name="requests",
            installed_version="2.28.0",
            latest_version="2.31.0",
        )
        assert report.is_outdated is True

    def test_package_report_not_outdated(self) -> None:
        report = PackageReport(
            name="requests",
            installed_version="2.31.0",
            latest_version="2.31.0",
        )
        assert report.is_outdated is False

    def test_scan_result_summary(self) -> None:
        result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="a",
                    installed_version="1.0",
                    latest_version="1.0",
                    status=HealthStatus.HEALTHY,
                ),
                PackageReport(
                    name="b",
                    installed_version="1.0",
                    latest_version="2.0",
                    status=HealthStatus.OUTDATED,
                ),
                PackageReport(
                    name="c",
                    installed_version="1.0",
                    latest_version="1.0",
                    status=HealthStatus.VULNERABLE,
                    vulnerabilities=[
                        Vulnerability(
                            "CVE-1", "test", "HIGH", "https://osv.dev/vulnerability/CVE-1"
                        )
                    ],
                ),
            ],
        )
        assert result.total == 3
        assert result.healthy_count == 1
        assert result.outdated_count == 1
        assert result.vulnerable_count == 1
        assert result.has_vulnerabilities() is True

    def test_scan_result_to_dict(self) -> None:
        result = ScanResult(project_path="/tmp/test")
        d = result.to_dict()
        assert "project_path" in d
        assert "summary" in d
        assert d["summary"]["total"] == 0


class TestOutput:
    """Tests for output rendering."""

    def test_render_json(self) -> None:
        from io import StringIO

        from rich.console import Console

        from depcheck.output import render_json

        result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.31.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
        )
        console = Console(file=StringIO())
        render_json(result, console=console)
        output = console.file.getvalue()
        assert "requests" in output

    def test_determine_exit_code_no_fail(self) -> None:
        from depcheck.output import determine_exit_code

        result = ScanResult(project_path="/tmp/test")
        assert determine_exit_code(result) == 0

    def test_determine_exit_code_vulnerable(self) -> None:
        from depcheck.output import determine_exit_code

        result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(name="x", installed_version="1.0", status=HealthStatus.VULNERABLE),
            ],
        )
        assert determine_exit_code(result, "vulnerable") == 1
        assert determine_exit_code(result, "outdated") == 0

    def test_determine_exit_code_any(self) -> None:
        from depcheck.output import determine_exit_code

        result = ScanResult(
            project_path="/tmp/test",
            packages=[
                PackageReport(name="x", installed_version="1.0", status=HealthStatus.OUTDATED),
            ],
        )
        assert determine_exit_code(result, "any") == 1

    def test_determine_exit_code_errors(self) -> None:
        from depcheck.output import determine_exit_code

        result = ScanResult(project_path="/tmp/test", errors=["No deps found"])
        assert determine_exit_code(result) == 2
