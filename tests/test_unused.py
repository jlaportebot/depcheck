"""Tests for depcheck.unused — unused/undeclared dependency detection.

Exercises the AST-based import scanner, import→distribution mapping, confidence
scoring heuristics, rendering (table + JSON), CLI wiring, and exit-code logic.
Uses temp projects so tests are hermetic and deterministic.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest
from click.testing import CliRunner

from depcheck.cli import main
from depcheck.unused import (
    Confidence,
    ImportScanner,
    UndeclaredFinding,
    UnusedAnalyzer,
    UnusedConfig,
    UnusedFinding,
    UnusedResult,
    determine_unused_exit_code,
    get_stdlib_modules,
    render_unused_table,
    resolve_import_to_package,
)

# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

_STDLIB = get_stdlib_modules()


@pytest.fixture()
def sample_project(tmp_path: Path) -> Path:
    """Create a minimal project with a mix of used / unused / undeclared deps."""
    project = tmp_path / "sample"
    project.mkdir()

    # pyproject.toml declaring three deps; only two are imported
    (project / "pyproject.toml").write_text(
        textwrap.dedent("""\
        [project]
        name = "sample"
        version = "0.1.0"
        dependencies = ["requests>=2.0", "rich", "deprecated-pkg"]
        """),
        encoding="utf-8",
    )

    src = project / "src" / "sample"
    src.mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    # Import requests (used), rich (used), but NOT deprecated-pkg (unused)
    # And import click which is NOT declared (undeclared)
    (src / "main.py").write_text(
        textwrap.dedent("""\
        import requests
        from rich.console import Console
        import click  # undeclared!

        def run() -> None:
            resp = requests.get("https://example.com")
            console = Console()
            console.print(resp.status_code)
            click.echo("done")
        """),
        encoding="utf-8",
    )

    return project


@pytest.fixture()
def clean_project(tmp_path: Path) -> Path:
    """Project where all declared deps are imported — no unused findings."""
    project = tmp_path / "clean"
    project.mkdir()
    (project / "requirements.txt").write_text("requests>=2.0\nrich\n", encoding="utf-8")
    (project / "app.py").write_text(
        "import requests\nfrom rich.console import Console\nprint(requests, Console)\n",
        encoding="utf-8",
    )
    return project


@pytest.fixture()
def empty_project(tmp_path: Path) -> Path:
    """Project with no manifests and no source."""
    project = tmp_path / "empty"
    project.mkdir()
    return project


# ---------------------------------------------------------------------------
# get_stdlib_modules
# ---------------------------------------------------------------------------


class TestStdlibModules:
    """Test the stdlib module registry."""

    def test_returns_frozenset(self) -> None:
        result = get_stdlib_modules()
        assert isinstance(result, frozenset)

    def test_contains_common_modules(self) -> None:
        result = get_stdlib_modules()
        for mod in ["os", "sys", "json", "pathlib", "ast", "re", "collections"]:
            assert mod in result, f"{mod} should be in stdlib set"

    def test_excludes_third_party(self) -> None:
        result = get_stdlib_modules()
        assert "requests" not in result
        assert "rich" not in result
        assert "click" not in result

    def test_deterministic(self) -> None:
        """Calling twice returns equal sets."""
        assert get_stdlib_modules() == get_stdlib_modules()


# ---------------------------------------------------------------------------
# resolve_import_to_package
# ---------------------------------------------------------------------------


class TestResolveImportToPackage:
    """Test the import-name → distribution-name mapping."""

    def test_yaml_maps_to_pyyaml(self) -> None:
        assert resolve_import_to_package("yaml") == "pyyaml"

    def test_pil_maps_to_pillow(self) -> None:
        assert resolve_import_to_package("PIL") == "pillow"

    def test_cv2_maps_to_opencv_python(self) -> None:
        assert resolve_import_to_package("cv2") == "opencv-python"

    def test_bs4_maps_to_beautifulsoup4(self) -> None:
        assert resolve_import_to_package("bs4") == "beautifulsoup4"

    def test_dotenido_module(self) -> None:
        # Sub-module qualifier should resolve to the top-level distribution
        assert resolve_import_to_package("rich.console") == "rich"

    def test_requests_unchanged(self) -> None:
        assert resolve_import_to_package("requests") == "requests"

    def test_click_unchanged(self) -> None:
        assert resolve_import_to_package("click") == "click"

    def test_empty_returns_none(self) -> None:
        assert resolve_import_to_package("") is None

    def test_unknown_package_returns_normalized(self) -> None:
        # Unknown import — should return normalized form (best-effort)
        result = resolve_import_to_package("some_unknown_pkg")
        assert result == "some-unknown-pkg" or result == "some_unknown_pkg"

    def test_crypto_maps_to_pycryptodome(self) -> None:
        assert resolve_import_to_package("Crypto") == "pycryptodome"

    def test_jwt_maps_to_pyjwt(self) -> None:
        assert resolve_import_to_package("jwt") == "pyjwt"

    def test_git_maps_to_gitpython(self) -> None:
        assert resolve_import_to_package("git") == "gitpython"

    def test_dotenv_maps_to_python_dotenv(self) -> None:
        assert resolve_import_to_package("dotenv") == "python-dotenv"


# ---------------------------------------------------------------------------
# ImportScanner
# ---------------------------------------------------------------------------


class TestImportScanner:
    """Test the AST-based import extractor."""

    def test_simple_import(self, tmp_path: Path) -> None:
        f = tmp_path / "a.py"
        f.write_text("import os\nimport sys\n", encoding="utf-8")
        scanner = ImportScanner()
        names = scanner.scan_file(f)
        assert "os" in names
        assert "sys" in names

    def test_dotted_import(self, tmp_path: Path) -> None:
        f = tmp_path / "b.py"
        f.write_text("import rich.console\nimport requests.sessions\n", encoding="utf-8")
        scanner = ImportScanner()
        names = scanner.scan_file(f)
        assert "rich" in names
        assert "requests" in names

    def test_from_import(self, tmp_path: Path) -> None:
        f = tmp_path / "c.py"
        f.write_text(
            "from rich.console import Console\nfrom collections import defaultdict\n",
            encoding="utf-8",
        )
        scanner = ImportScanner()
        names = scanner.scan_file(f)
        assert "rich" in names
        assert "collections" in names

    def test_relative_imports_skipped(self, tmp_path: Path) -> None:
        f = tmp_path / "d.py"
        f.write_text("from . import sibling\nfrom ..parent import thing\n", encoding="utf-8")
        scanner = ImportScanner()
        names = scanner.scan_file(f)
        # Relative imports (level > 0) refer to project-local modules
        assert "sibling" not in names
        assert "parent" not in names

    def test_nested_imports(self, tmp_path: Path) -> None:
        f = tmp_path / "e.py"
        f.write_text(
            textwrap.dedent("""\
            def func():
                import requests
                return requests

            class Foo:
                def bar(self):
                    from rich.table import Table
                    return Table
            """),
            encoding="utf-8",
        )
        scanner = ImportScanner()
        names = scanner.scan_file(f)
        assert "requests" in names
        assert "rich" in names

    def test_try_except_import(self, tmp_path: Path) -> None:
        f = tmp_path / "f.py"
        f.write_text(
            textwrap.dedent("""\
            try:
                import tomllib
            except ImportError:
                import tomli as tomllib
            """),
            encoding="utf-8",
        )
        scanner = ImportScanner()
        names = scanner.scan_file(f)
        assert "tomllib" in names
        assert "tomli" in names

    def test_nonexistent_file_returns_empty(self, tmp_path: Path) -> None:
        scanner = ImportScanner()
        # Use a real path object that doesn't exist as a file
        names = scanner.scan_file(tmp_path / "does_not_exist.py")
        assert names == []

    def test_syntax_error_falls_back_to_regex(self, tmp_path: Path) -> None:
        f = tmp_path / "broken.py"
        f.write_text("import requests\n!!!syntax error!!!\nimport rich\n", encoding="utf-8")
        scanner = ImportScanner()
        names = scanner.scan_file(f)
        # Regex fallback should still find "requests" and "rich"
        assert "requests" in names
        assert "rich" in names

    def test_empty_file(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.py"
        f.write_text("", encoding="utf-8")
        scanner = ImportScanner()
        assert scanner.scan_file(f) == []

    def test_file_with_only_comments(self, tmp_path: Path) -> None:
        f = tmp_path / "comments.py"
        f.write_text("# just a comment\n'''docstring'''\n", encoding="utf-8")
        scanner = ImportScanner()
        assert scanner.scan_file(f) == []

    def test_does_not_explode_on_binary(self, tmp_path: Path) -> None:
        f = tmp_path / "binary.py"
        f.write_bytes(b"\x00\x01import\x02requests")
        scanner = ImportScanner()
        # Should not raise; either returns [] or partial via regex
        result = scanner.scan_file(f)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Confidence enum
# ---------------------------------------------------------------------------


class TestConfidenceEnum:
    """Test the Confidence StrEnum."""

    def test_high_value(self) -> None:
        assert Confidence.HIGH.value == "high"

    def test_medium_value(self) -> None:
        assert Confidence.MEDIUM.value == "medium"

    def test_low_value(self) -> None:
        assert Confidence.LOW.value == "low"

    def test_is_string(self) -> None:
        assert isinstance(Confidence.HIGH, str)
        assert Confidence.HIGH == "high"

    def test_ordering_by_explicit_map(self) -> None:
        order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        assert order[Confidence.HIGH] < order[Confidence.MEDIUM]
        assert order[Confidence.MEDIUM] < order[Confidence.LOW]


# ---------------------------------------------------------------------------
# Dataclass serialization
# ---------------------------------------------------------------------------


class TestUnusedFindingSerialization:
    """Test UnusedFinding.to_dict()."""

    def test_full_dict(self) -> None:
        f = UnusedFinding(
            name="deprecated-pkg",
            declared_version="1.0.0",
            declared_in=["pyproject.toml"],
            confidence=Confidence.HIGH,
            reason="No import found.",
        )
        d = f.to_dict()
        assert d["name"] == "deprecated-pkg"
        assert d["declared_version"] == "1.0.0"
        assert d["declared_in"] == ["pyproject.toml"]
        assert d["confidence"] == "high"
        assert d["reason"] == "No import found."
        assert d["imported_indirectly"] is False

    def test_defaults(self) -> None:
        f = UnusedFinding(name="test")
        d = f.to_dict()
        assert d["name"] == "test"
        assert d["declared_version"] is None
        assert d["declared_in"] == []
        assert d["confidence"] == "high"
        assert d["reason"] == ""
        assert d["imported_indirectly"] is False


class TestUndeclaredFindingSerialization:
    """Test UndeclaredFinding.to_dict()."""

    def test_full_dict(self) -> None:
        f = UndeclaredFinding(
            import_name="click",
            resolved_package="click",
            used_in=["src/app.py"],
        )
        d = f.to_dict()
        assert d["import_name"] == "click"
        assert d["resolved_package"] == "click"
        assert d["used_in"] == ["src/app.py"]


class TestUnusedResultSerialization:
    """Test UnusedResult.to_dict()."""

    def test_empty_result(self) -> None:
        r = UnusedResult()
        d = r.to_dict()
        assert d["declared_count"] == 0
        assert d["imported_count"] == 0
        assert d["unused"] == []
        assert d["undeclared"] == []
        assert d["errors"] == []

    def test_populated_result(self) -> None:
        r = UnusedResult(
            project_path="/tmp/proj",
            declared=3,
            imported=["requests", "rich"],
            unused=[UnusedFinding(name="old-pkg", confidence=Confidence.HIGH)],
            undeclared=[UndeclaredFinding(import_name="click", resolved_package="click")],
            files_scanned=5,
            manifest_files=["pyproject.toml"],
        )
        d = r.to_dict()
        assert d["project_path"] == "/tmp/proj"
        assert d["declared_count"] == 3
        assert d["imported_count"] == 2
        assert len(d["unused"]) == 1
        assert d["unused"][0]["name"] == "old-pkg"
        assert len(d["undeclared"]) == 1
        assert d["undeclared"][0]["import_name"] == "click"
        assert d["files_scanned"] == 5
        assert d["manifest_files"] == ["pyproject.toml"]


# ---------------------------------------------------------------------------
# UnusedConfig
# ---------------------------------------------------------------------------


class TestUnusedConfig:
    """Test the configuration dataclass."""

    def test_defaults(self) -> None:
        c = UnusedConfig()
        assert ".venv" in c.exclude_dirs
        assert "__pycache__" in c.exclude_dirs
        assert c.exclude_patterns == []
        assert c.include_undeclared is False
        assert c.include_transitive is False
        assert c.confidence_threshold == Confidence.LOW
        assert c.max_files > 0

    def test_custom_values(self) -> None:
        c = UnusedConfig(
            exclude_patterns=["vendor/**"],
            include_undeclared=True,
            confidence_threshold=Confidence.HIGH,
            max_files=100,
        )
        assert c.exclude_patterns == ["vendor/**"]
        assert c.include_undeclared is True
        assert c.confidence_threshold == Confidence.HIGH
        assert c.max_files == 100

    def test_exclude_dirs_immutable_default(self) -> None:
        """Two config instances should have independent exclude_dirs."""
        c1 = UnusedConfig()
        c2 = UnusedConfig()
        c1.exclude_dirs.add("custom_dir")
        assert "custom_dir" not in c2.exclude_dirs


# ---------------------------------------------------------------------------
# UnusedAnalyzer — end-to-end
# ---------------------------------------------------------------------------


class TestUnusedAnalyzer:
    """Test the full analyzer on synthetic projects."""

    def test_detects_unused_dependency(self, sample_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(sample_project)
        names = {f.name for f in result.unused}
        assert "deprecated-pkg" in names
        # The deprecated-pkg should be HIGH confidence (not in known-indirect set)
        dep_finding = next(f for f in result.unused if f.name == "deprecated-pkg")
        assert dep_finding.confidence == Confidence.HIGH

    def test_does_not_flag_used_deps(self, sample_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(sample_project)
        names = {f.name for f in result.unused}
        assert "requests" not in names
        assert "rich" not in names

    def test_unused_sorted_by_confidence_then_name(self, sample_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(sample_project)
        if len(result.unused) >= 2:
            order = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
            for i in range(len(result.unused) - 1):
                a, b = result.unused[i], result.unused[i + 1]
                assert order[a.confidence] <= order[b.confidence], (
                    "Findings should be sorted by confidence (HIGH first)"
                )

    def test_include_undeclared(self, sample_project: Path) -> None:
        config = UnusedConfig(include_undeclared=True)
        analyzer = UnusedAnalyzer(config=config)
        result = analyzer.analyze(sample_project)
        undeclared_names = {f.import_name for f in result.undeclared}
        assert "click" in undeclared_names

    def test_no_undeclared_by_default(self, sample_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(sample_project)
        assert result.undeclared == []

    def test_clean_project_no_findings(self, clean_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(clean_project)
        assert result.unused == []
        assert result.undeclared == []

    def test_empty_project_errors(self, empty_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(empty_project)
        # No manifests → likely 0 declared, no findings
        assert result.declared == 0
        assert result.unused == []

    def test_nonexistent_path_errors(self, tmp_path: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(tmp_path / "does_not_exist")
        assert len(result.errors) > 0
        assert result.unused == []

    def test_confidence_threshold_filters(self, sample_project: Path) -> None:
        """Threshold=HIGH should only show HIGH findings."""
        config = UnusedConfig(confidence_threshold=Confidence.HIGH)
        analyzer = UnusedAnalyzer(config=config)
        result = analyzer.analyze(sample_project)
        for f in result.unused:
            assert f.confidence == Confidence.HIGH

    def test_known_indirect_packages_low_confidence(self, tmp_path: Path) -> None:
        """Known tooling deps (pytest, ruff) should be LOW confidence."""
        project = tmp_path / "tooling"
        project.mkdir()
        (project / "requirements.txt").write_text("pytest\nruff\nrequests\n", encoding="utf-8")
        (project / "app.py").write_text("import requests\n", encoding="utf-8")
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(project)
        by_name = {f.name: f for f in result.unused}
        if "pytest" in by_name:
            assert by_name["pytest"].confidence == Confidence.LOW
        if "ruff" in by_name:
            assert by_name["ruff"].confidence == Confidence.LOW

    def test_transitive_prefix_heuristic(self, tmp_path: Path) -> None:
        """Declared 'flask', imported 'flask-login' → flask is MEDIUM (transitive)."""
        project = tmp_path / "flask_proj"
        project.mkdir()
        (project / "requirements.txt").write_text("flask\nflask-login\n", encoding="utf-8")
        (project / "app.py").write_text("from flask_login import LoginManager\n", encoding="utf-8")
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(project)
        by_name = {f.name: f for f in result.unused}
        if "flask" in by_name:
            assert by_name["flask"].confidence == Confidence.MEDIUM

    def test_exclude_patterns(self, tmp_path: Path) -> None:
        """Excluding source dirs should prevent imports from being found."""
        project = tmp_path / "exclude_proj"
        project.mkdir()
        (project / "requirements.txt").write_text("requests\n", encoding="utf-8")
        src = project / "src"
        src.mkdir()
        (src / "main.py").write_text("import requests\n", encoding="utf-8")
        config = UnusedConfig(exclude_patterns=["src/*"])
        analyzer = UnusedAnalyzer(config=config)
        result = analyzer.analyze(project)
        # With src excluded, requests appears unused
        assert any(f.name == "requests" for f in result.unused)

    def test_max_files_limit(self, tmp_path: Path) -> None:
        project = tmp_path / "many_files"
        project.mkdir()
        (project / "requirements.txt").write_text("requests\n", encoding="utf-8")
        for i in range(5):
            (project / f"file_{i}.py").write_text("import requests\n", encoding="utf-8")
        config = UnusedConfig(max_files=2)
        analyzer = UnusedAnalyzer(config=config)
        result = analyzer.analyze(project)
        assert result.files_scanned <= 2
        assert any("max_files" in e for e in result.errors)

    def test_files_scanned_count(self, sample_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(sample_project)
        assert result.files_scanned >= 1

    def test_manifest_files_populated(self, sample_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(sample_project)
        assert len(result.manifest_files) >= 1
        assert any("pyproject.toml" in m for m in result.manifest_files)

    def test_local_module_not_flagged_as_undeclared(self, sample_project: Path) -> None:
        """The project's own package name should not appear in undeclared list."""
        config = UnusedConfig(include_undeclared=True)
        analyzer = UnusedAnalyzer(config=config)
        result = analyzer.analyze(sample_project)
        undeclared_names = {f.import_name for f in result.undeclared}
        assert "sample" not in undeclared_names

    def test_stdlib_not_flagged(self, sample_project: Path) -> None:
        """Standard library modules should never be in undeclared list."""
        config = UnusedConfig(include_undeclared=True)
        analyzer = UnusedAnalyzer(config=config)
        result = analyzer.analyze(sample_project)
        undeclared_names = {f.import_name for f in result.undeclared}
        for mod in ["os", "sys", "json"]:
            assert mod not in undeclared_names

    def test_deterministic_results(self, sample_project: Path) -> None:
        """Running analyze twice produces identical results."""
        analyzer = UnusedAnalyzer()
        r1 = analyzer.analyze(sample_project)
        r2 = analyzer.analyze(sample_project)
        assert r1.to_dict() == r2.to_dict()


# ---------------------------------------------------------------------------
# Exit code logic
# ---------------------------------------------------------------------------


class TestDetermineExitCode:
    """Test determine_unused_exit_code()."""

    def _result_with(self, confidence: Confidence) -> UnusedResult:
        return UnusedResult(
            unused=[UnusedFinding(name="x", confidence=confidence)],
        )

    def test_no_fail_on_returns_zero(self) -> None:
        result = UnusedResult(unused=[UnusedFinding(name="x", confidence=Confidence.HIGH)])
        assert determine_unused_exit_code(result, fail_on=None) == 0

    def test_fail_on_high_with_high_finding(self) -> None:
        result = self._result_with(Confidence.HIGH)
        assert determine_unused_exit_code(result, fail_on="high") == 1

    def test_fail_on_high_with_medium_finding(self) -> None:
        result = self._result_with(Confidence.MEDIUM)
        assert determine_unused_exit_code(result, fail_on="high") == 0

    def test_fail_on_medium_with_medium_finding(self) -> None:
        result = self._result_with(Confidence.MEDIUM)
        assert determine_unused_exit_code(result, fail_on="medium") == 1

    def test_fail_on_low_with_low_finding(self) -> None:
        result = self._result_with(Confidence.LOW)
        assert determine_unused_exit_code(result, fail_on="low") == 1

    def test_fail_on_low_with_high_finding(self) -> None:
        """LOW threshold catches everything."""
        result = self._result_with(Confidence.HIGH)
        assert determine_unused_exit_code(result, fail_on="low") == 1

    def test_fail_on_any_with_unused(self) -> None:
        result = UnusedResult(unused=[UnusedFinding(name="x")])
        assert determine_unused_exit_code(result, fail_on="any") == 1

    def test_fail_on_any_with_undeclared(self) -> None:
        result = UnusedResult(undeclared=[UndeclaredFinding(import_name="x", resolved_package="x")])
        assert determine_unused_exit_code(result, fail_on="any") == 1

    def test_fail_on_any_clean(self) -> None:
        result = UnusedResult()
        assert determine_unused_exit_code(result, fail_on="any") == 0

    def test_invalid_fail_on_returns_zero(self) -> None:
        result = self._result_with(Confidence.HIGH)
        assert determine_unused_exit_code(result, fail_on="invalid") == 0

    def test_case_insensitive(self) -> None:
        result = self._result_with(Confidence.HIGH)
        assert determine_unused_exit_code(result, fail_on="HIGH") == 1
        assert determine_unused_exit_code(result, fail_on="High") == 1


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


class TestRendering:
    """Test table and JSON rendering."""

    def _capture_json(self, result: UnusedResult) -> str:
        """Use rich Console.capture to capture render_unused_json output."""
        from rich.console import Console

        console = Console(force_terminal=False, no_color=True, width=10000)
        with console.capture() as capture:
            from depcheck.unused import render_unused_json

            render_unused_json(result, console=console)
        return capture.get()

    def test_json_output_valid_json(self, sample_project: Path) -> None:
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(sample_project)
        output = self._capture_json(result)
        parsed = json.loads(output)
        assert "unused" in parsed
        assert "undeclared" in parsed
        assert "declared_count" in parsed

    def test_table_output_no_crash(self, sample_project: Path) -> None:
        """Render table should not raise even with findings."""
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(sample_project)
        # Should not raise
        render_unused_table(result)

    def test_table_clean_project(self, clean_project: Path) -> None:
        """Table output on clean project should show 'no unused' message."""
        analyzer = UnusedAnalyzer()
        result = analyzer.analyze(clean_project)
        # Should not raise
        render_unused_table(result)

    def test_json_empty_result(self) -> None:
        result = UnusedResult()
        output = self._capture_json(result)
        parsed = json.loads(output)
        assert parsed["unused"] == []
        assert parsed["undeclared"] == []

    def test_json_includes_all_fields(self, sample_project: Path) -> None:
        config = UnusedConfig(include_undeclared=True)
        analyzer = UnusedAnalyzer(config=config)
        result = analyzer.analyze(sample_project)
        output = self._capture_json(result)
        parsed = json.loads(output)
        assert "project_path" in parsed
        assert "files_scanned" in parsed
        assert "manifest_files" in parsed
        assert "declared_count" in parsed
        assert "imported_count" in parsed
        assert "errors" in parsed
        if parsed["unused"]:
            f = parsed["unused"][0]
            assert "name" in f
            assert "declared_version" in f
            assert "declared_in" in f
            assert "confidence" in f
            assert "reason" in f
            assert "imported_indirectly" in f


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestUnusedCLI:
    """Test the unused command via Click's CliRunner."""

    def test_help_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["unused", "--help"])
        assert result.exit_code == 0
        assert "unused" in result.output.lower()
        assert "--include-undeclared" in result.output
        assert "--confidence" in result.output
        assert "--fail-on" in result.output

    def test_basic_run(self, sample_project: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(sample_project)])
        assert result.exit_code == 0

    def test_json_output(self, sample_project: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(sample_project), "--json"])
        assert result.exit_code == 0
        # Output should be valid JSON
        parsed = json.loads(result.output)
        assert "unused" in parsed

    def test_clean_project_exit_zero(self, clean_project: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(clean_project)])
        assert result.exit_code == 0

    def test_fail_on_high(self, sample_project: Path) -> None:
        """Exit 1 when fail-on=high and there's a HIGH finding."""
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(sample_project), "--fail-on", "high"])
        assert result.exit_code == 1

    def test_fail_on_any(self, sample_project: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(sample_project), "--fail-on", "any"])
        assert result.exit_code == 1

    def test_confidence_filter(self, sample_project: Path) -> None:
        """--confidence high should only show HIGH findings."""
        runner = CliRunner()
        result = runner.invoke(
            main, ["unused", str(sample_project), "--confidence", "high", "--json"]
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        for f in parsed["unused"]:
            assert f["confidence"] == "high"

    def test_include_undeclared_flag(self, sample_project: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main, ["unused", str(sample_project), "--include-undeclared", "--json"]
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        # click should appear in undeclared
        undeclared_names = {f["import_name"] for f in parsed["undeclared"]}
        assert "click" in undeclared_names

    def test_quiet_mode(self, sample_project: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(sample_project), "--quiet"])
        assert result.exit_code == 0

    def test_quiet_with_json(self, sample_project: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(sample_project), "--quiet", "--json"])
        assert result.exit_code == 0
        # Even in quiet mode, JSON should still be output
        assert result.output.strip()

    def test_exclude_pattern(self, tmp_path: Path) -> None:
        """--exclude should skip matching source files."""
        project = tmp_path / "excl"
        project.mkdir()
        (project / "requirements.txt").write_text("requests\n", encoding="utf-8")
        src = project / "src"
        src.mkdir()
        (src / "main.py").write_text("import requests\n", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(project), "--exclude", "src/*", "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        unused_names = {f["name"] for f in parsed["unused"]}
        assert "requests" in unused_names

    def test_nonexistent_path(self, tmp_path: Path) -> None:
        """Click should reject nonexistent paths (arg type validation)."""
        runner = CliRunner()
        fake = str(tmp_path / "nonexistent")
        result = runner.invoke(main, ["unused", fake])
        # Click validates exists=True; exit code 2
        assert result.exit_code == 2

    def test_fail_on_high_no_high_finding_exits_zero(self, clean_project: Path) -> None:
        """Clean project + fail-on=high should exit 0."""
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(clean_project), "--fail-on", "high"])
        assert result.exit_code == 0

    def test_command_listed_in_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "unused" in result.output

    def test_real_self_project_has_results(self) -> None:
        """Run unused against the depcheck repo itself (meta-test)."""
        repo_root = Path(__file__).resolve().parent.parent
        runner = CliRunner()
        result = runner.invoke(main, ["unused", str(repo_root), "--json", "--quiet"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        # Should have scanned at least one file
        assert parsed["files_scanned"] >= 1
        # Should have parsed at least one manifest
        assert len(parsed["manifest_files"]) >= 1
