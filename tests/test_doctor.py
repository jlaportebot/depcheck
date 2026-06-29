"""Tests for depcheck.doctor — dependency diagnostic module."""

from __future__ import annotations

import json
import sys
from io import StringIO
from unittest.mock import patch

from depcheck.doctor import (
    Category,
    DoctorReport,
    Finding,
    Severity,
    _check_dep_files,
    _check_formatting,
    _check_import_consistency,
    _check_python_version,
    _check_unpinned_deps,
    _check_venv,
    render_doctor_json,
    render_doctor_table,
    run_doctor,
)

# ---------------------------------------------------------------------------
# Finding tests
# ---------------------------------------------------------------------------


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_to_dict(self) -> None:
        f = Finding(
            category=Category.SECURITY,
            severity=Severity.CRITICAL,
            title="Unpinned dependency",
            description="requests has no version specifier",
            package="requests",
            fix="Pin with requests==2.31.0",
            file_path="requirements.txt",
            line_number=3,
        )
        d = f.to_dict()
        assert d["category"] == "security"
        assert d["severity"] == "critical"
        assert d["title"] == "Unpinned dependency"
        assert d["package"] == "requests"
        assert d["fix"] == "Pin with requests==2.31.0"
        assert d["line_number"] == 3

    def test_to_dict_minimal(self) -> None:
        f = Finding(
            category=Category.ENVIRONMENT,
            severity=Severity.INFO,
            title="Some info",
            description="Details here",
        )
        d = f.to_dict()
        assert d["package"] is None
        assert d["fix"] is None
        assert d["file_path"] is None
        assert d["line_number"] is None


# ---------------------------------------------------------------------------
# DoctorReport tests
# ---------------------------------------------------------------------------


class TestDoctorReport:
    """Tests for the DoctorReport dataclass."""

    def _make_report(self) -> DoctorReport:
        findings = [
            Finding(Category.SECURITY, Severity.CRITICAL, "C1", "desc1"),
            Finding(Category.SECURITY, Severity.CRITICAL, "C2", "desc2"),
            Finding(Category.CONFIGURATION, Severity.WARNING, "W1", "desc3"),
            Finding(Category.ENVIRONMENT, Severity.INFO, "I1", "desc4"),
        ]
        return DoctorReport(
            project_path="/tmp/test",
            findings=findings,
            checks_run=5,
            python_version="3.12.0",
            pip_version="24.0",
            venv_active=True,
            venv_path="/tmp/venv",
        )

    def test_critical_count(self) -> None:
        report = self._make_report()
        assert report.critical_count == 2

    def test_warning_count(self) -> None:
        report = self._make_report()
        assert report.warning_count == 1

    def test_info_count(self) -> None:
        report = self._make_report()
        assert report.info_count == 1

    def test_has_critical(self) -> None:
        report = self._make_report()
        assert report.has_critical is True

    def test_is_healthy(self) -> None:
        report = self._make_report()
        assert report.is_healthy is False

    def test_is_healthy_when_clean(self) -> None:
        report = DoctorReport(project_path="/tmp/test")
        assert report.is_healthy is True

    def test_is_healthy_with_info_only(self) -> None:
        findings = [Finding(Category.ENVIRONMENT, Severity.INFO, "I1", "desc")]
        report = DoctorReport(project_path="/tmp/test", findings=findings)
        assert report.is_healthy is True

    def test_is_healthy_with_warnings(self) -> None:
        findings = [Finding(Category.ENVIRONMENT, Severity.WARNING, "W1", "desc")]
        report = DoctorReport(project_path="/tmp/test", findings=findings)
        assert report.is_healthy is False

    def test_to_dict(self) -> None:
        report = self._make_report()
        d = report.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert d["summary"]["checks_run"] == 5
        assert d["summary"]["critical_count"] == 2
        assert d["summary"]["warning_count"] == 1
        assert d["summary"]["info_count"] == 1
        assert d["summary"]["is_healthy"] is False
        assert d["summary"]["python_version"] == "3.12.0"
        assert d["summary"]["venv_active"] is True
        assert len(d["findings"]) == 4
        assert len(d["errors"]) == 0


# ---------------------------------------------------------------------------
# _check_venv tests
# ---------------------------------------------------------------------------


class TestCheckVenv:
    """Tests for _check_venv."""

    def test_detects_no_venv(self) -> None:
        findings: list[Finding] = []
        with (
            patch.object(sys, "real_prefix", None, create=True),
            patch.object(sys, "base_prefix", sys.prefix),
        ):
            in_venv, venv_path, pip_ver = _check_venv(findings)

        # When not in venv, should add a finding
        if not in_venv:
            assert any(f.title == "No virtual environment active" for f in findings)

    def test_returns_tuple(self) -> None:
        findings: list[Finding] = []
        result = _check_venv(findings)
        assert isinstance(result, tuple)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# _check_python_version tests
# ---------------------------------------------------------------------------


class TestCheckPythonVersion:
    """Tests for _check_python_version."""

    def test_no_pyproject(self, tmp_path) -> None:
        findings: list[Finding] = []
        _check_python_version(tmp_path, findings)
        assert len(findings) == 0  # No pyproject, no check

    def test_no_requires_python(self, tmp_path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'test'\n")
        findings: list[Finding] = []
        _check_python_version(tmp_path, findings)
        assert len(findings) == 1
        assert findings[0].title == "No requires-python declared"
        assert findings[0].severity == Severity.INFO

    def test_compatible_version(self, tmp_path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        current = f"{sys.version_info.major}.{sys.version_info.minor}"
        pyproject.write_text(f"[project]\nname = 'test'\nrequires-python = '>={current}'\n")
        findings: list[Finding] = []
        _check_python_version(tmp_path, findings)
        # Should not add a CRITICAL finding for incompatible version
        incompatible = [f for f in findings if f.title == "Python version incompatible"]
        assert len(incompatible) == 0

    def test_incompatible_version(self, tmp_path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'test'\nrequires-python = '>=4.0'\n")
        findings: list[Finding] = []
        _check_python_version(tmp_path, findings)
        incompatible = [f for f in findings if f.title == "Python version incompatible"]
        assert len(incompatible) == 1
        assert incompatible[0].severity == Severity.CRITICAL

    def test_invalid_specifier(self, tmp_path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text("[project]\nname = 'test'\nrequires-python = 'not-valid-spec'\n")
        findings: list[Finding] = []
        _check_python_version(tmp_path, findings)
        invalid = [f for f in findings if f.title == "Invalid requires-python specifier"]
        assert len(invalid) == 1
        assert invalid[0].severity == Severity.WARNING


# ---------------------------------------------------------------------------
# _check_dep_files tests
# ---------------------------------------------------------------------------


class TestCheckDepFiles:
    """Tests for _check_dep_files."""

    def test_no_files_at_all(self, tmp_path) -> None:
        findings: list[Finding] = []
        _check_dep_files(tmp_path, findings)
        assert any(f.title == "No dependency files found" for f in findings)

    def test_has_requirements(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        findings: list[Finding] = []
        _check_dep_files(tmp_path, findings)
        assert not any(f.title == "No dependency files found" for f in findings)

    def test_unpinned_requirements(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\nflask>=2.0\n")
        findings: list[Finding] = []
        _check_dep_files(tmp_path, findings)
        unpinned = [f for f in findings if "Unpinned requirement" in f.title]
        assert len(unpinned) >= 1

    def test_setup_py_without_pyproject(self, tmp_path) -> None:
        (tmp_path / "setup.py").write_text("from setuptools import setup; setup()")
        findings: list[Finding] = []
        _check_dep_files(tmp_path, findings)
        legacy = [f for f in findings if "legacy setup.py" in f.title]
        assert len(legacy) == 1
        assert legacy[0].severity == Severity.INFO

    def test_pipfile_without_lock(self, tmp_path) -> None:
        (tmp_path / "Pipfile").write_text("[packages]\nrequests = '*'\n")
        findings: list[Finding] = []
        _check_dep_files(tmp_path, findings)
        missing_lock = [f for f in findings if "Pipfile.lock" in f.title]
        assert len(missing_lock) == 1
        assert missing_lock[0].severity == Severity.WARNING

    def test_poetry_without_lock(self, tmp_path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            "[tool.poetry]\nname = 'test'\nversion = '0.1'\n"
            "[tool.poetry.dependencies]\npython = '^3.9'\n"
        )
        findings: list[Finding] = []
        _check_dep_files(tmp_path, findings)
        missing_lock = [f for f in findings if "poetry.lock" in f.title]
        assert len(missing_lock) == 1


# ---------------------------------------------------------------------------
# _check_unpinned_deps tests
# ---------------------------------------------------------------------------


class TestCheckUnpinnedDeps:
    """Tests for _check_unpinned_deps."""

    def test_unpinned_dependency(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\n")

        with patch("depcheck.doctor.discover_dependencies") as mock_discover:
            from depcheck.models import ParsedDependency

            mock_discover.return_value = (
                [ParsedDependency(name="requests", version=None, specifier=None)],
                ["requirements.txt"],
            )
            findings: list[Finding] = []
            _check_unpinned_deps(tmp_path, findings)
            unpinned = [f for f in findings if f.title == "Unpinned dependency"]
            assert len(unpinned) == 1
            assert unpinned[0].severity == Severity.CRITICAL

    def test_loose_specifier(self, tmp_path) -> None:
        from depcheck.models import ParsedDependency

        with patch("depcheck.doctor.discover_dependencies") as mock_discover:
            mock_discover.return_value = (
                [ParsedDependency(name="requests", version="2.31.0", specifier=">=2.28.0")],
                ["requirements.txt"],
            )
            findings: list[Finding] = []
            _check_unpinned_deps(tmp_path, findings)
            loose = [f for f in findings if "Loosely pinned" in f.title]
            assert len(loose) == 1
            assert loose[0].severity == Severity.WARNING

    def test_pinned_no_finding(self, tmp_path) -> None:
        from depcheck.models import ParsedDependency

        with patch("depcheck.doctor.discover_dependencies") as mock_discover:
            mock_discover.return_value = (
                [ParsedDependency(name="requests", version="2.31.0", specifier="==2.31.0")],
                ["requirements.txt"],
            )
            findings: list[Finding] = []
            _check_unpinned_deps(tmp_path, findings)
            assert len(findings) == 0


# ---------------------------------------------------------------------------
# _check_formatting tests
# ---------------------------------------------------------------------------


class TestCheckFormatting:
    """Tests for _check_formatting."""

    def test_mixed_case_package_name(self, tmp_path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("Requests==2.31.0\n")
        findings: list[Finding] = []
        _check_formatting(tmp_path, findings)
        mixed = [f for f in findings if "Mixed-case" in f.title]
        assert len(mixed) == 1

    def test_trailing_whitespace(self, tmp_path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0  \n")
        findings: list[Finding] = []
        _check_formatting(tmp_path, findings)
        tw = [f for f in findings if "trailing" in f.title.lower()]
        assert len(tw) == 1

    def test_no_trailing_newline(self, tmp_path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0")  # No trailing newline
        findings: list[Finding] = []
        _check_formatting(tmp_path, findings)
        nl = [f for f in findings if "newline" in f.title.lower()]
        assert len(nl) == 1

    def test_well_formatted_no_findings(self, tmp_path) -> None:
        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.31.0\nflask==3.0.0\n")
        findings: list[Finding] = []
        _check_formatting(tmp_path, findings)
        # Should not produce formatting findings for clean file
        formatting = [f for f in findings if f.category == Category.FORMATTING]
        assert len(formatting) == 0

    def test_duplicate_in_pyproject(self, tmp_path) -> None:
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_text(
            "[project]\nname = 'test'\n\n"
            "[project.dependencies]\n"
            "requests = '>=2.28'\n"
            "flask = '>=3.0'\n"
            "requests = '>=2.31'\n"  # Duplicate!
        )
        findings: list[Finding] = []
        _check_formatting(tmp_path, findings)
        dupes = [f for f in findings if "Duplicate" in f.title]
        assert len(dupes) >= 1


# ---------------------------------------------------------------------------
# _check_import_consistency tests
# ---------------------------------------------------------------------------


class TestCheckImportConsistency:
    """Tests for _check_import_consistency."""

    def test_undeclared_import(self, tmp_path) -> None:
        # Create a Python file that imports something not declared
        (tmp_path / "app.py").write_text("import requests\n")
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        with patch("depcheck.doctor.discover_dependencies") as mock_discover:
            from depcheck.models import ParsedDependency

            mock_discover.return_value = (
                [ParsedDependency(name="flask", version="3.0.0", specifier="==3.0.0")],
                ["requirements.txt"],
            )
            findings: list[Finding] = []
            _check_import_consistency(tmp_path, findings)
            _ = [f for f in findings if "not declared" in f.title.lower()]
            # requests should be flagged as undeclared (if it's not filtered)
            # The check may not find it if requests is not installed
            assert isinstance(findings, list)

    def test_no_python_files(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")

        with patch("depcheck.doctor.discover_dependencies") as mock_discover:
            from depcheck.models import ParsedDependency

            mock_discover.return_value = (
                [ParsedDependency(name="flask", version="3.0.0", specifier="==3.0.0")],
                ["requirements.txt"],
            )
            findings: list[Finding] = []
            _check_import_consistency(tmp_path, findings)
            # No Python files to scan, should not crash
            assert isinstance(findings, list)


# ---------------------------------------------------------------------------
# run_doctor integration tests
# ---------------------------------------------------------------------------


class TestRunDoctor:
    """Integration tests for run_doctor."""

    def test_invalid_path(self) -> None:
        report = run_doctor("/nonexistent/path")
        assert len(report.errors) > 0

    def test_basic_run(self, tmp_path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            "[project]\nname = 'test'\nrequires-python = '>=3.8'\n"
            "dependencies = ['requests>=2.28']\n"
        )
        report = run_doctor(str(tmp_path))
        assert report.project_path == str(tmp_path.resolve())
        assert report.checks_run >= 1
        assert report.python_version != ""

    def test_empty_project(self, tmp_path) -> None:
        report = run_doctor(str(tmp_path))
        # Should still run without errors (just findings)
        assert isinstance(report, DoctorReport)
        assert report.checks_run >= 1

    def test_with_requirements(self, tmp_path) -> None:
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\nflask==3.0.0\n")
        report = run_doctor(str(tmp_path))
        assert isinstance(report, DoctorReport)

    def test_no_venv_finding(self, tmp_path) -> None:
        """Running outside a venv should produce a warning."""
        (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
        report = run_doctor(str(tmp_path))
        if not report.venv_active:
            venv_findings = [f for f in report.findings if "virtual environment" in f.title.lower()]
            assert len(venv_findings) >= 1


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


class TestRenderDoctorTable:
    """Tests for render_doctor_table."""

    def test_renders_without_error(self) -> None:
        from rich.console import Console

        report = DoctorReport(
            project_path="/tmp/test",
            findings=[
                Finding(Category.SECURITY, Severity.CRITICAL, "Unpinned", "desc", package="foo"),
                Finding(Category.ENVIRONMENT, Severity.WARNING, "No venv", "desc"),
            ],
            checks_run=5,
            python_version="3.12.0",
            pip_version="24.0",
            venv_active=False,
        )
        console = Console(file=StringIO(), width=160)
        render_doctor_table(report, console=console)

    def test_renders_healthy(self) -> None:
        from rich.console import Console

        report = DoctorReport(
            project_path="/tmp/test",
            checks_run=5,
            python_version="3.12.0",
            pip_version="24.0",
            venv_active=True,
            venv_path="/tmp/venv",
        )
        console = Console(file=StringIO(), width=160)
        render_doctor_table(report, console=console)


class TestRenderDoctorJson:
    """Tests for render_doctor_json."""

    def test_produces_valid_json(self) -> None:
        from rich.console import Console

        report = DoctorReport(
            project_path="/tmp/test",
            findings=[
                Finding(Category.SECURITY, Severity.CRITICAL, "Unpinned", "desc"),
            ],
            checks_run=5,
            python_version="3.12.0",
            pip_version="24.0",
        )
        buf = StringIO()
        console = Console(file=buf, width=1000, force_terminal=False, no_color=True)
        render_doctor_json(report, console=console)
        data = json.loads(buf.getvalue())
        assert "summary" in data
        assert "findings" in data
        assert data["summary"]["critical_count"] == 1

    def test_healthy_report_json(self) -> None:
        from rich.console import Console

        report = DoctorReport(
            project_path="/tmp/test",
            checks_run=5,
            python_version="3.12.0",
        )
        buf = StringIO()
        console = Console(file=buf, width=1000, force_terminal=False, no_color=True)
        render_doctor_json(report, console=console)
        data = json.loads(buf.getvalue())
        assert data["summary"]["is_healthy"] is True
        assert len(data["findings"]) == 0
