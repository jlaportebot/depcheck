"""Tests for the depcheck diff command and module."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from depcheck.cli import main
from depcheck.diff import (
    DiffType,
    DiffResult,
    PackageDiff,
    compare_dependencies,
    diff_files,
    detect_lockfile_drift,
    generate_unified_diff,
    parse_dependency_file,
    render_diff_json,
    render_diff_table,
)
from depcheck.models import ParsedDependency


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_requirements(tmp: Path, name: str, content: str) -> Path:
    """Write a requirements-style file to tmp/name and return its path."""
    p = tmp / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# PackageDiff
# ---------------------------------------------------------------------------

class TestPackageDiff:
    """Unit tests for PackageDiff dataclass."""

    def test_symbol_and_color(self) -> None:
        pkg = PackageDiff(name="foo", diff_type=DiffType.ADDED)
        assert pkg.symbol == "+"
        assert pkg.color == "green"

    def test_removed_style(self) -> None:
        pkg = PackageDiff(name="bar", diff_type=DiffType.REMOVED)
        assert pkg.symbol == "-"
        assert pkg.color == "red"

    def test_upgraded_style(self) -> None:
        pkg = PackageDiff(name="baz", diff_type=DiffType.UPGRADED)
        assert pkg.symbol == "↑"
        assert pkg.color == "green"

    def test_downgraded_style(self) -> None:
        pkg = PackageDiff(name="baz", diff_type=DiffType.DOWNGRADED)
        assert pkg.symbol == "↓"
        assert pkg.color == "red"

    def test_specifier_changed_style(self) -> None:
        pkg = PackageDiff(name="x", diff_type=DiffType.SPECIFIER_CHANGED)
        assert pkg.symbol == "~"
        assert pkg.color == "yellow"

    def test_unpinned_style(self) -> None:
        pkg = PackageDiff(name="y", diff_type=DiffType.UNPINNED)
        assert pkg.symbol == "⚠"
        assert pkg.color == "yellow"

    def test_pinned_style(self) -> None:
        pkg = PackageDiff(name="z", diff_type=DiffType.PINNED)
        assert pkg.symbol == "✓"
        assert pkg.color == "green"

    def test_unchanged_style(self) -> None:
        pkg = PackageDiff(name="w", diff_type=DiffType.UNCHANGED)
        assert pkg.symbol == "="
        assert pkg.color == "dim"

    def test_to_dict(self) -> None:
        pkg = PackageDiff(
            name="requests",
            diff_type=DiffType.UPGRADED,
            old_version="2.28.0",
            new_version="2.31.0",
            old_specifier=">=2.28.0",
            new_specifier=">=2.31.0",
        )
        d = pkg.to_dict()
        assert d["name"] == "requests"
        assert d["change"] == "upgraded"
        assert d["old_version"] == "2.28.0"
        assert d["new_version"] == "2.31.0"
        assert d["old_specifier"] == ">=2.28.0"
        assert d["new_specifier"] == ">=2.31.0"


# ---------------------------------------------------------------------------
# DiffResult
# ---------------------------------------------------------------------------

class TestDiffResult:
    """Unit tests for DiffResult dataclass."""

    def _make_result(self) -> DiffResult:
        return DiffResult(
            old_source="old.txt",
            new_source="new.txt",
            packages=[
                PackageDiff(name="a", diff_type=DiffType.ADDED),
                PackageDiff(name="b", diff_type=DiffType.REMOVED),
                PackageDiff(name="c", diff_type=DiffType.UPGRADED),
                PackageDiff(name="d", diff_type=DiffType.DOWNGRADED),
                PackageDiff(name="e", diff_type=DiffType.UNCHANGED),
                PackageDiff(name="f", diff_type=DiffType.SPECIFIER_CHANGED),
            ],
            old_total=5,
            new_total=6,
        )

    def test_counts(self) -> None:
        r = self._make_result()
        assert r.added_count == 1
        assert r.removed_count == 1
        assert r.changed_count == 3  # upgraded + downgraded + specifier_changed
        assert r.unchanged_count == 1

    def test_to_dict(self) -> None:
        r = self._make_result()
        d = r.to_dict()
        assert d["old_source"] == "old.txt"
        assert d["new_source"] == "new.txt"
        assert d["summary"]["added"] == 1
        assert d["summary"]["removed"] == 1
        assert d["summary"]["changed"] == 3
        assert d["summary"]["unchanged"] == 1
        assert len(d["packages"]) == 6

    def test_empty_result(self) -> None:
        r = DiffResult(old_source="a", new_source="b")
        assert r.added_count == 0
        assert r.removed_count == 0
        assert r.changed_count == 0
        assert r.unchanged_count == 0


# ---------------------------------------------------------------------------
# compare_dependencies
# ---------------------------------------------------------------------------

class TestCompareDependencies:
    """Unit tests for compare_dependencies."""

    def test_added_packages(self) -> None:
        old = [ParsedDependency(name="requests", version="2.28.0")]
        new = [
            ParsedDependency(name="requests", version="2.28.0"),
            ParsedDependency(name="flask", version="3.0.0"),
        ]
        diffs = compare_dependencies(old, new)
        added = [d for d in diffs if d.diff_type == DiffType.ADDED]
        assert len(added) == 1
        assert added[0].name == "flask"

    def test_removed_packages(self) -> None:
        old = [
            ParsedDependency(name="requests", version="2.28.0"),
            ParsedDependency(name="flask", version="3.0.0"),
        ]
        new = [ParsedDependency(name="requests", version="2.28.0")]
        diffs = compare_dependencies(old, new)
        removed = [d for d in diffs if d.diff_type == DiffType.REMOVED]
        assert len(removed) == 1
        assert removed[0].name == "flask"

    def test_upgraded_package(self) -> None:
        old = [ParsedDependency(name="requests", version="2.28.0")]
        new = [ParsedDependency(name="requests", version="2.31.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.UPGRADED
        assert diffs[0].old_version == "2.28.0"
        assert diffs[0].new_version == "2.31.0"

    def test_downgraded_package(self) -> None:
        old = [ParsedDependency(name="requests", version="2.31.0")]
        new = [ParsedDependency(name="requests", version="2.28.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.DOWNGRADED

    def test_unchanged_package(self) -> None:
        old = [ParsedDependency(name="requests", version="2.28.0")]
        new = [ParsedDependency(name="requests", version="2.28.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.UNCHANGED

    def test_specifier_changed(self) -> None:
        old = [ParsedDependency(name="requests", version="2.28.0", specifier=">=2.28.0")]
        new = [ParsedDependency(name="requests", version="2.28.0", specifier=">=2.31.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.SPECIFIER_CHANGED

    def test_unpinned_from_pinned(self) -> None:
        old = [ParsedDependency(name="requests", version="2.28.0")]
        new = [ParsedDependency(name="requests", version=None, specifier=">=2.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.UNPINNED

    def test_pinned_from_unpinned(self) -> None:
        old = [ParsedDependency(name="requests", version=None, specifier=">=2.0")]
        new = [ParsedDependency(name="requests", version="2.31.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.PINNED

    def test_both_no_version_unchanged(self) -> None:
        old = [ParsedDependency(name="requests", version=None)]
        new = [ParsedDependency(name="requests", version=None)]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.UNCHANGED

    def test_both_no_version_specifier_changed(self) -> None:
        old = [ParsedDependency(name="requests", version=None, specifier=">=2.0")]
        new = [ParsedDependency(name="requests", version=None, specifier=">=3.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.SPECIFIER_CHANGED

    def test_empty_sets(self) -> None:
        diffs = compare_dependencies([], [])
        assert diffs == []

    def test_multiple_changes(self) -> None:
        old = [
            ParsedDependency(name="requests", version="2.28.0"),
            ParsedDependency(name="flask", version="2.0.0"),
            ParsedDependency(name="numpy", version="1.24.0"),
        ]
        new = [
            ParsedDependency(name="requests", version="2.31.0"),
            ParsedDependency(name="flask", version="3.0.0"),
            ParsedDependency(name="pandas", version="2.0.0"),
        ]
        diffs = compare_dependencies(old, new)
        by_name = {d.name: d for d in diffs}
        assert by_name["requests"].diff_type == DiffType.UPGRADED
        assert by_name["flask"].diff_type == DiffType.UPGRADED
        assert by_name["numpy"].diff_type == DiffType.REMOVED
        assert by_name["pandas"].diff_type == DiffType.ADDED

    def test_pre_release_version_comparison(self) -> None:
        old = [ParsedDependency(name="foo", version="1.0.0a1")]
        new = [ParsedDependency(name="foo", version="1.0.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.UPGRADED

    def test_same_version_different_specifier(self) -> None:
        old = [ParsedDependency(name="foo", version="1.0.0", specifier="==1.0.0")]
        new = [ParsedDependency(name="foo", version="1.0.0", specifier=">=1.0.0")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        assert diffs[0].diff_type == DiffType.SPECIFIER_CHANGED

    def test_unparseable_version_falls_back_to_string(self) -> None:
        old = [ParsedDependency(name="foo", version="abc")]
        new = [ParsedDependency(name="foo", version="xyz")]
        diffs = compare_dependencies(old, new)
        assert len(diffs) == 1
        # Falls back to string comparison, "xyz" > "abc" so upgraded
        assert diffs[0].diff_type in (DiffType.UPGRADED, DiffType.DOWNGRADED)


# ---------------------------------------------------------------------------
# diff_files
# ---------------------------------------------------------------------------

class TestDiffFiles:
    """Integration tests for diff_files using temp files."""

    def test_diff_requirements_files(self, tmp_path: Path) -> None:
        old_file = _write_requirements(
            tmp_path,
            "old.txt",
            """\
            requests==2.28.0
            flask==2.0.0
            numpy==1.24.0
            """,
        )
        new_file = _write_requirements(
            tmp_path,
            "new.txt",
            """\
            requests==2.31.0
            flask==2.0.0
            pandas==2.0.0
            """,
        )
        result = diff_files(old_file, new_file)
        assert result.old_total == 3
        assert result.new_total == 3
        by_name = {d.name: d for d in result.packages}
        assert by_name["requests"].diff_type == DiffType.UPGRADED
        assert by_name["flask"].diff_type == DiffType.UNCHANGED
        assert by_name["numpy"].diff_type == DiffType.REMOVED
        assert by_name["pandas"].diff_type == DiffType.ADDED

    def test_diff_no_changes(self, tmp_path: Path) -> None:
        old_file = _write_requirements(
            tmp_path, "old.txt", "requests==2.28.0\nflask==2.0.0\n"
        )
        new_file = _write_requirements(
            tmp_path, "new.txt", "requests==2.28.0\nflask==2.0.0\n"
        )
        result = diff_files(old_file, new_file)
        assert result.unchanged_count == 2
        assert result.added_count == 0
        assert result.removed_count == 0
        assert result.changed_count == 0

    def test_diff_nonexistent_file(self, tmp_path: Path) -> None:
        real_file = _write_requirements(tmp_path, "real.txt", "requests==1.0\n")
        result = diff_files(real_file, tmp_path / "nonexistent.txt")
        assert result.packages == []

    def test_diff_empty_files(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "")
        new_file = _write_requirements(tmp_path, "new.txt", "")
        result = diff_files(old_file, new_file)
        assert result.old_total == 0
        assert result.new_total == 0

    def test_diff_all_added(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "")
        new_file = _write_requirements(tmp_path, "new.txt", "requests==2.31.0\nflask==3.0.0\n")
        result = diff_files(old_file, new_file)
        assert result.added_count == 2
        assert result.removed_count == 0

    def test_diff_all_removed(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "requests==2.31.0\nflask==3.0.0\n")
        new_file = _write_requirements(tmp_path, "new.txt", "")
        result = diff_files(old_file, new_file)
        assert result.removed_count == 2
        assert result.added_count == 0


# ---------------------------------------------------------------------------
# generate_unified_diff
# ---------------------------------------------------------------------------

class TestUnifiedDiff:
    """Tests for the unified diff output."""

    def test_basic_unified_diff(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "requests==2.28.0\nflask==2.0.0\n")
        new_file = _write_requirements(tmp_path, "new.txt", "requests==2.31.0\nflask==2.0.0\n")
        diff = generate_unified_diff(old_file, new_file)
        assert "-requests==2.28.0" in diff or "-requests" in diff
        assert "+requests==2.31.0" in diff or "+requests" in diff

    def test_no_changes_unified(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "same.txt", "flask==2.0.0\n")
        new_file = _write_requirements(tmp_path, "same2.txt", "flask==2.0.0\n")
        diff = generate_unified_diff(old_file, new_file)
        assert diff == ""

    def test_nonexistent_files(self, tmp_path: Path) -> None:
        diff = generate_unified_diff(tmp_path / "no1.txt", tmp_path / "no2.txt")
        assert diff == ""


# ---------------------------------------------------------------------------
# detect_lockfile_drift
# ---------------------------------------------------------------------------

class TestLockfileDrift:
    """Tests for lockfile drift detection."""

    def test_no_drift(self, tmp_path: Path) -> None:
        manifest = _write_requirements(tmp_path, "req.txt", "requests==2.31.0\n")
        lockfile = _write_requirements(tmp_path, "req.lock", "requests==2.31.0\n")
        result = detect_lockfile_drift(manifest, lockfile)
        # Only changes shown, unchanged filtered out
        assert len(result.packages) == 0

    def test_drift_detected(self, tmp_path: Path) -> None:
        manifest = _write_requirements(tmp_path, "req.txt", "requests>=2.28.0\n")
        lockfile = _write_requirements(tmp_path, "req.lock", "requests==2.31.0\n")
        result = detect_lockfile_drift(manifest, lockfile)
        # There should be some diff (specifier or version change)
        assert len(result.packages) >= 1

    def test_drift_nonexistent(self, tmp_path: Path) -> None:
        manifest = _write_requirements(tmp_path, "req.txt", "requests==1.0\n")
        result = detect_lockfile_drift(manifest, tmp_path / "no.lock")
        assert result.packages == []


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class TestRendering:
    """Tests for diff rendering (table and JSON)."""

    def test_render_table_no_changes(self, capsys: pytest.CaptureFixture[str]) -> None:
        from rich.console import Console

        result = DiffResult(
            old_source="a.txt",
            new_source="b.txt",
            packages=[
                PackageDiff(name="x", diff_type=DiffType.UNCHANGED, old_version="1.0", new_version="1.0"),
            ],
            old_total=1,
            new_total=1,
        )
        console = Console(width=120, force_terminal=True)
        render_diff_table(result, console=console)
        # Should not crash; output captured

    def test_render_table_with_changes(self) -> None:
        from io import StringIO
        from rich.console import Console

        result = DiffResult(
            old_source="a.txt",
            new_source="b.txt",
            packages=[
                PackageDiff(name="requests", diff_type=DiffType.UPGRADED, old_version="2.28", new_version="2.31"),
                PackageDiff(name="flask", diff_type=DiffType.ADDED, new_version="3.0"),
                PackageDiff(name="numpy", diff_type=DiffType.REMOVED, old_version="1.24"),
            ],
            old_total=2,
            new_total=2,
        )
        buf = StringIO()
        console = Console(file=buf, width=120, force_terminal=True)
        render_diff_table(result, console=console)
        output = buf.getvalue()
        assert "requests" in output
        assert "flask" in output
        assert "numpy" in output

    def test_render_json_output(self) -> None:
        from io import StringIO
        from rich.console import Console

        result = DiffResult(
            old_source="a.txt",
            new_source="b.txt",
            packages=[
                PackageDiff(name="x", diff_type=DiffType.ADDED, new_version="1.0"),
            ],
            old_total=0,
            new_total=1,
        )
        buf = StringIO()
        console = Console(file=buf, width=120, no_color=True)
        render_diff_json(result, console=console)
        data = json.loads(buf.getvalue())
        assert data["summary"]["added"] == 1
        assert data["packages"][0]["name"] == "x"


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------

class TestDiffCLI:
    """Integration tests for `depcheck diff` CLI command."""

    def test_diff_cli_basic(self, tmp_path: Path) -> None:
        old_file = _write_requirements(
            tmp_path, "old.txt", "requests==2.28.0\nflask==2.0.0\n"
        )
        new_file = _write_requirements(
            tmp_path, "new.txt", "requests==2.31.0\nflask==2.0.0\npandas==2.0.0\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(old_file), str(new_file)])
        assert result.exit_code == 0
        assert "requests" in result.output or "Dependency Changes" in result.output

    def test_diff_cli_json(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "requests==2.28.0\n")
        new_file = _write_requirements(tmp_path, "new.txt", "requests==2.31.0\n")
        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--json", str(old_file), str(new_file)])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["changed"] >= 1

    def test_diff_cli_unified(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "requests==2.28.0\n")
        new_file = _write_requirements(tmp_path, "new.txt", "requests==2.31.0\n")
        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--unified", str(old_file), str(new_file)])
        assert result.exit_code == 0

    def test_diff_cli_fail_on_change_with_changes(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "requests==2.28.0\n")
        new_file = _write_requirements(tmp_path, "new.txt", "requests==2.31.0\n")
        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--fail-on-change", str(old_file), str(new_file)])
        assert result.exit_code == 1

    def test_diff_cli_fail_on_change_no_changes(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "requests==2.28.0\n")
        new_file = _write_requirements(tmp_path, "new.txt", "requests==2.28.0\n")
        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--fail-on-change", str(old_file), str(new_file)])
        assert result.exit_code == 0

    def test_diff_cli_drift(self, tmp_path: Path) -> None:
        manifest = _write_requirements(tmp_path, "req.txt", "requests>=2.0\n")
        lockfile = _write_requirements(tmp_path, "req.lock", "requests==2.31.0\n")
        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--drift", str(manifest), str(lockfile)])
        assert result.exit_code == 0

    def test_diff_cli_quiet(self, tmp_path: Path) -> None:
        old_file = _write_requirements(tmp_path, "old.txt", "requests==2.28.0\n")
        new_file = _write_requirements(tmp_path, "new.txt", "requests==2.31.0\n")
        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--quiet", str(old_file), str(new_file)])
        assert result.exit_code == 0

    def test_diff_cli_no_differences(self, tmp_path: Path) -> None:
        same = _write_requirements(tmp_path, "same.txt", "requests==2.28.0\n")
        same2 = _write_requirements(tmp_path, "same2.txt", "requests==2.28.0\n")
        runner = CliRunner()
        result = runner.invoke(main, ["diff", str(same), str(same2)])
        assert result.exit_code == 0

    def test_diff_cli_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["diff", "--help"])
        assert result.exit_code == 0
        assert "Compare two dependency files" in result.output
        assert "--json" in result.output
        assert "--unified" in result.output
        assert "--drift" in result.output
        assert "--fail-on-change" in result.output
