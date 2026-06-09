"""Tests for the stack module — tech stack detection and compliance analysis."""

from __future__ import annotations

import json
from io import StringIO
from unittest.mock import patch

from depcheck.stack import (
    ConflictSeverity,
    LicenseChainEntry,
    PythonCompatEntry,
    StackCategory,
    StackComponent,
    StackConflict,
    StackResult,
    _detect_project_files,
    _detect_project_type,
    _detect_python_version,
    check_license_chain,
    check_python_compat,
    classify_package,
    detect_conflicts,
    render_stack_json,
    render_stack_table,
    run_stack,
)

# ---------------------------------------------------------------------------
# Unit tests for classify_package
# ---------------------------------------------------------------------------


class TestClassifyPackage:
    """Tests for classify_package."""

    def test_django(self) -> None:
        assert classify_package("django") == StackCategory.WEB_FRAMEWORK

    def test_flask(self) -> None:
        assert classify_package("flask") == StackCategory.WEB_FRAMEWORK

    def test_fastapi(self) -> None:
        assert classify_package("fastapi") == StackCategory.WEB_FRAMEWORK

    def test_pytest(self) -> None:
        assert classify_package("pytest") == StackCategory.TESTING

    def test_ruff(self) -> None:
        assert classify_package("ruff") == StackCategory.LINTING

    def test_mypy(self) -> None:
        # mypy is in both LINTING and TYPE_CHECKING; first match wins
        cat = classify_package("mypy")
        assert cat in (StackCategory.LINTING, StackCategory.TYPE_CHECKING)

    def test_requests(self) -> None:
        assert classify_package("requests") == StackCategory.HTTP_CLIENT

    def test_httpx(self) -> None:
        assert classify_package("httpx") == StackCategory.HTTP_CLIENT

    def test_sqlalchemy(self) -> None:
        assert classify_package("sqlalchemy") == StackCategory.ORM

    def test_celery(self) -> None:
        assert classify_package("celery") == StackCategory.TASK_QUEUE

    def test_pandas(self) -> None:
        assert classify_package("pandas") == StackCategory.DATA_SCIENCE

    def test_torch(self) -> None:
        assert classify_package("torch") == StackCategory.ML_AI

    def test_unknown_package(self) -> None:
        assert classify_package("nonexistent-package-xyz") == StackCategory.UNKNOWN

    def test_normalized_name(self) -> None:
        # Normalize should handle hyphens/underscores
        cat = classify_package("pytest-asyncio")
        assert cat == StackCategory.TESTING


# ---------------------------------------------------------------------------
# Unit tests for detect_conflicts
# ---------------------------------------------------------------------------


class TestDetectConflicts:
    """Tests for detect_conflicts."""

    def test_no_conflicts(self) -> None:
        conflicts = detect_conflicts(["click", "rich", "httpx"])
        assert len(conflicts) == 0

    def test_django_flask_conflict(self) -> None:
        conflicts = detect_conflicts(["django", "flask"])
        assert len(conflicts) >= 1
        django_flask = [c for c in conflicts if "django" in c.packages and "flask" in c.packages]
        assert len(django_flask) == 1
        assert django_flask[0].severity == ConflictSeverity.WARNING

    def test_ruff_flake8_conflict(self) -> None:
        conflicts = detect_conflicts(["ruff", "flake8"])
        lint_conflicts = [c for c in conflicts if "ruff" in c.packages]
        assert len(lint_conflicts) >= 1

    def test_ruff_isort_conflict(self) -> None:
        conflicts = detect_conflicts(["ruff", "isort"])
        assert any("isort" in c.packages for c in conflicts)

    def test_ruff_black_conflict(self) -> None:
        conflicts = detect_conflicts(["ruff", "black"])
        assert any("black" in c.packages for c in conflicts)

    def test_mypy_pyright_conflict(self) -> None:
        conflicts = detect_conflicts(["mypy", "pyright"])
        assert any("mypy" in c.packages and "pyright" in c.packages for c in conflicts)

    def test_requests_httpx_conflict(self) -> None:
        conflicts = detect_conflicts(["requests", "httpx"])
        assert any("requests" in c.packages and "httpx" in c.packages for c in conflicts)

    def test_no_self_conflict(self) -> None:
        # Single package in a rule shouldn't trigger
        conflicts = detect_conflicts(["django"])
        django_conflicts = [
            c for c in conflicts if "django" in c.packages and "flask" in c.packages
        ]
        assert len(django_conflicts) == 0

    def test_multiple_conflicts(self) -> None:
        conflicts = detect_conflicts(["ruff", "flake8", "isort", "black"])
        assert len(conflicts) >= 2


# ---------------------------------------------------------------------------
# Unit tests for check_python_compat
# ---------------------------------------------------------------------------


class TestCheckPythonCompat:
    """Tests for check_python_compat."""

    def test_compatible_package(self) -> None:
        entry = check_python_compat("django", "4.2", (3, 11))
        assert entry.is_compatible is True

    def test_incompatible_package(self) -> None:
        entry = check_python_compat("django", "5.0", (3, 9))
        assert entry.is_compatible is False
        assert "3.10" in entry.note

    def test_unknown_package(self) -> None:
        entry = check_python_compat("unknown-pkg", "1.0.0", (3, 11))
        assert entry.is_compatible is True  # No data = assume compatible
        assert "No compatibility data" in entry.note

    def test_no_version(self) -> None:
        entry = check_python_compat("django", None, (3, 11))
        assert "Version unknown" in entry.note

    def test_numpy_compat(self) -> None:
        entry = check_python_compat("numpy", "2.0", (3, 8))
        assert entry.is_compatible is False  # numpy 2.0 requires 3.9+


# ---------------------------------------------------------------------------
# Unit tests for check_license_chain
# ---------------------------------------------------------------------------


class TestCheckLicenseChain:
    """Tests for check_license_chain."""

    def test_all_permissive(self) -> None:
        licenses = [
            ("pkg-a", "MIT", "permissive"),
            ("pkg-b", "Apache-2.0", "permissive"),
            ("pkg-c", "BSD-3-Clause", "permissive"),
        ]
        entries = check_license_chain(licenses)
        assert len(entries) == 3
        assert all(e.is_compatible for e in entries)
        assert all(not e.conflict_with for e in entries)

    def test_copyleft_detected(self) -> None:
        licenses = [
            ("pkg-a", "MIT", "permissive"),
            ("pkg-b", "GPL-3.0", "copyleft"),
        ]
        entries = check_license_chain(licenses)
        copyleft_entries = [e for e in entries if e.license_id == "GPL-3.0"]
        assert len(copyleft_entries) == 1
        assert "Copyleft" in copyleft_entries[0].note

    def test_copyleft_conflicts_flagged(self) -> None:
        licenses = [
            ("pkg-a", "MIT", "permissive"),
            ("pkg-b", "GPL-3.0", "copyleft"),
        ]
        entries = check_license_chain(licenses)
        permissive_entries = [e for e in entries if e.license_id == "MIT"]
        assert len(permissive_entries) == 1
        assert len(permissive_entries[0].conflict_with) > 0

    def test_unknown_license(self) -> None:
        licenses = [
            ("pkg-a", "UNKNOWN", "unknown"),
        ]
        entries = check_license_chain(licenses)
        assert "unknown" in entries[0].note.lower() or "risk" in entries[0].note.lower()

    def test_agpl_detection(self) -> None:
        licenses = [
            ("pkg-a", "AGPL-3.0", "copyleft"),
        ]
        entries = check_license_chain(licenses)
        assert any("Copyleft" in e.note for e in entries)

    def test_empty_list(self) -> None:
        entries = check_license_chain([])
        assert len(entries) == 0


# ---------------------------------------------------------------------------
# Unit tests for _detect_project_type
# ---------------------------------------------------------------------------


class TestDetectProjectType:
    """Tests for _detect_project_type."""

    def test_django_project(self, tmp_path: object) -> None:

        project = tmp_path  # type: ignore
        (project / "manage.py").write_text("# django")
        result = _detect_project_type(project)
        assert "django" in result

    def test_containerized_project(self, tmp_path: object) -> None:

        project = tmp_path  # type: ignore
        (project / "Dockerfile").write_text("FROM python:3.11")
        result = _detect_project_type(project)
        assert "containerized" in result

    def test_plain_project(self, tmp_path: object) -> None:

        project = tmp_path  # type: ignore
        result = _detect_project_type(project)
        assert result == "python_library"


# ---------------------------------------------------------------------------
# Unit tests for _detect_project_files
# ---------------------------------------------------------------------------


class TestDetectProjectFiles:
    """Tests for _detect_project_files."""

    def test_common_files(self, tmp_path: object) -> None:

        project = tmp_path  # type: ignore
        (project / "pyproject.toml").write_text("[project]")
        (project / "requirements.txt").write_text("click>=8.0")
        (project / "Dockerfile").write_text("FROM python:3.11")

        files = _detect_project_files(project)
        assert "pyproject.toml" in files
        assert "requirements.txt" in files
        assert "Dockerfile" in files

    def test_no_notable_files(self, tmp_path: object) -> None:

        project = tmp_path  # type: ignore
        files = _detect_project_files(project)
        assert len(files) == 0


# ---------------------------------------------------------------------------
# Unit tests for _detect_python_version
# ---------------------------------------------------------------------------


class TestDetectPythonVersion:
    """Tests for _detect_python_version."""

    def test_from_pyproject_toml(self, tmp_path: object) -> None:

        project = tmp_path  # type: ignore
        (project / "pyproject.toml").write_text('[project]\nrequires-python = ">=3.10"\n')
        version = _detect_python_version(project)
        assert version == "3.10"

    def test_from_poetry(self, tmp_path: object) -> None:

        project = tmp_path  # type: ignore
        (project / "pyproject.toml").write_text('[tool.poetry.dependencies]\npython = ">=3.9"\n')
        version = _detect_python_version(project)
        assert version == "3.9"

    def test_fallback_to_runtime(self, tmp_path: object) -> None:

        project = tmp_path  # type: ignore
        import sys

        version = _detect_python_version(project)
        major, minor = version.split(".")
        assert int(major) == sys.version_info.major


# ---------------------------------------------------------------------------
# Unit tests for serialization
# ---------------------------------------------------------------------------


class TestSerialization:
    """Tests for to_dict serialization."""

    def test_stack_component_to_dict(self) -> None:
        sc = StackComponent(
            package_name="django",
            category=StackCategory.WEB_FRAMEWORK,
            version="4.2",
        )
        d = sc.to_dict()
        assert d["package_name"] == "django"
        assert d["category"] == "web_framework"

    def test_stack_conflict_to_dict(self) -> None:
        sc = StackConflict(
            packages=["django", "flask"],
            severity=ConflictSeverity.WARNING,
            message="Both are web frameworks",
        )
        d = sc.to_dict()
        assert d["severity"] == "warning"
        assert len(d["packages"]) == 2

    def test_python_compat_entry_to_dict(self) -> None:
        entry = PythonCompatEntry(
            package_name="django",
            version="5.0",
            min_python=(3, 10),
            current_python=(3, 9),
            is_compatible=False,
        )
        d = entry.to_dict()
        assert d["min_python"] == "3.10"
        assert d["current_python"] == "3.9"
        assert d["is_compatible"] is False

    def test_license_chain_entry_to_dict(self) -> None:
        entry = LicenseChainEntry(
            package_name="pkg-a",
            license_id="MIT",
            category="permissive",
            is_compatible=True,
            conflict_with=["pkg-b"],
        )
        d = entry.to_dict()
        assert d["license_id"] == "MIT"
        assert len(d["conflict_with"]) == 1

    def test_stack_result_to_dict(self) -> None:
        result = StackResult(
            project_path="/test",
            project_type="django+containerized",
            python_version="3.11",
            components=[
                StackComponent(
                    package_name="django",
                    category=StackCategory.WEB_FRAMEWORK,
                    version="4.2",
                ),
            ],
            categories={"web_framework": ["django"]},
            conflicts=[
                StackConflict(
                    packages=["django", "flask"],
                    severity=ConflictSeverity.WARNING,
                    message="Both are web frameworks",
                ),
            ],
            stack_summary={"web_framework": 1},
        )
        d = result.to_dict()
        assert d["project_type"] == "django+containerized"
        assert len(d["components"]) == 1
        assert len(d["conflicts"]) == 1

    def test_json_roundtrip(self) -> None:
        result = StackResult(
            project_path="/test",
            python_version="3.11",
            components=[
                StackComponent(package_name="a", category=StackCategory.CLI),
                StackComponent(package_name="b", category=StackCategory.TESTING),
            ],
            categories={"cli": ["a"], "testing": ["b"]},
            stack_summary={"cli": 1, "testing": 1},
        )
        data = json.dumps(result.to_dict())
        parsed = json.loads(data)
        assert parsed["project_path"] == "/test"
        assert len(parsed["components"]) == 2


# ---------------------------------------------------------------------------
# Unit tests for rendering
# ---------------------------------------------------------------------------


class TestRendering:
    """Tests for render functions."""

    def test_render_stack_table(self) -> None:
        result = StackResult(
            project_path="/test",
            project_type="python_library",
            python_version="3.11",
            components=[
                StackComponent(
                    package_name="click",
                    category=StackCategory.CLI,
                    version="8.1.0",
                ),
                StackComponent(
                    package_name="pytest",
                    category=StackCategory.TESTING,
                    version="7.4.0",
                ),
            ],
            categories={"cli": ["click"], "testing": ["pytest"]},
            conflicts=[
                StackConflict(
                    packages=["ruff", "flake8"],
                    severity=ConflictSeverity.WARNING,
                    message="Ruff can replace flake8",
                ),
            ],
            stack_summary={"cli": 1, "testing": 1},
        )
        render_stack_table(result)

    def test_render_stack_table_with_licenses(self) -> None:
        result = StackResult(
            project_path="/test",
            project_type="python_library",
            python_version="3.11",
            components=[
                StackComponent(
                    package_name="pkg-a",
                    category=StackCategory.HTTP_CLIENT,
                ),
            ],
            categories={"http_client": ["pkg-a"]},
            license_chain=[
                LicenseChainEntry(
                    package_name="pkg-a",
                    license_id="MIT",
                    category="permissive",
                    is_compatible=True,
                ),
                LicenseChainEntry(
                    package_name="pkg-b",
                    license_id="GPL-3.0",
                    category="copyleft",
                    conflict_with=["pkg-a"],
                    note="Permissive license may be incompatible with copyleft: pkg-b",
                ),
            ],
            stack_summary={"http_client": 1},
        )
        render_stack_table(result)

    def test_render_stack_json(self) -> None:
        result = StackResult(
            project_path="/test",
            python_version="3.11",
            components=[
                StackComponent(package_name="test", category=StackCategory.CLI),
            ],
        )
        from rich.console import Console

        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_stack_json(result, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert data["project_path"] == "/test"


# ---------------------------------------------------------------------------
# Integration tests for run_stack with mocked deps
# ---------------------------------------------------------------------------


class TestRunStackMocked:
    """Tests for run_stack with mocked dependencies."""

    def test_basic_stack_analysis(self) -> None:

        from depcheck.models import ParsedDependency

        mock_deps = [
            ParsedDependency(name="click", version="8.1.0"),
            ParsedDependency(name="pytest", version="7.4.0"),
        ]

        with patch("depcheck.stack.discover_dependencies") as mock_discover:
            mock_discover.return_value = (mock_deps, ["pyproject.toml"])

            # Create a temp project dir
            import tempfile

            with tempfile.TemporaryDirectory() as tmpdir:
                result = run_stack(tmpdir)
                assert result.project_type is not None
                assert len(result.components) == 2
                # Check categories
                assert "cli" in result.categories or "testing" in result.categories

    def test_stack_with_conflicts(self) -> None:
        from depcheck.models import ParsedDependency

        mock_deps = [
            ParsedDependency(name="django", version="4.2"),
            ParsedDependency(name="flask", version="3.0"),
        ]

        with patch("depcheck.stack.discover_dependencies") as mock_discover:
            mock_discover.return_value = (mock_deps, ["pyproject.toml"])

            import tempfile

            with tempfile.TemporaryDirectory() as tmpdir:
                result = run_stack(tmpdir)
                assert len(result.conflicts) >= 1

    def test_invalid_path(self) -> None:
        result = run_stack("/nonexistent/path")
        assert len(result.errors) > 0
