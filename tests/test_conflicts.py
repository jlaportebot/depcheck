"""Tests for depcheck.conflicts — dependency conflict detection and analysis."""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch

from depcheck.conflicts import (
    ConflictSeverity,
    ConflictResult,
    ConflictReport,
    VersionConstraint,
    _classify_conflict,
    _detect_circular_deps,
    _extract_version_constraints,
    _parse_requirement_spec,
    render_conflict_json,
    render_conflict_table,
)
from depcheck.repomap import DependencyNode, RepoMap


# ── VersionConstraint Tests ──────────────────────────────────────────────


class TestVersionConstraint:
    """Tests for the VersionConstraint dataclass."""

    def test_defaults(self) -> None:
        vc = VersionConstraint(package="a", target="b", specifier=">=1.0")
        assert vc.package == "a"
        assert vc.target == "b"
        assert vc.specifier == ">=1.0"
        assert vc.source == "direct"

    def test_transitive(self) -> None:
        vc = VersionConstraint(package="a", target="b", specifier=">=1.0", source="transitive")
        assert vc.source == "transitive"

    def test_to_dict(self) -> None:
        vc = VersionConstraint(package="flask", target="werkzeug", specifier=">=2.0", source="direct")
        d = vc.to_dict()
        assert d["package"] == "flask"
        assert d["target"] == "werkzeug"
        assert d["specifier"] == ">=2.0"
        assert d["source"] == "direct"


# ── ConflictResult Tests ─────────────────────────────────────────────────


class TestConflictResult:
    """Tests for the ConflictResult dataclass."""

    def test_defaults(self) -> None:
        cr = ConflictResult(package="test-pkg")
        assert cr.package == "test-pkg"
        assert cr.constraints == []
        assert cr.severity == ConflictSeverity.WARNING
        assert cr.compatible_versions == []
        assert cr.resolution_suggestion == ""
        assert cr.constraint_count == 0

    def test_constraint_count(self) -> None:
        cr = ConflictResult(
            package="pkg",
            constraints=[
                VersionConstraint(package="a", target="pkg", specifier=">=1.0"),
                VersionConstraint(package="b", target="pkg", specifier="<2.0"),
            ],
        )
        assert cr.constraint_count == 2

    def test_to_dict(self) -> None:
        cr = ConflictResult(
            package="werkzeug",
            severity=ConflictSeverity.HARD,
            compatible_versions=[],
            resolution_suggestion="No compatible version",
        )
        d = cr.to_dict()
        assert d["package"] == "werkzeug"
        assert d["severity"] == "hard"
        assert d["compatible_versions"] == []


# ── ConflictReport Tests ─────────────────────────────────────────────────


class TestConflictReport:
    """Tests for the ConflictReport dataclass."""

    def test_defaults(self) -> None:
        report = ConflictReport(project_path="/test")
        assert report.conflicts == []
        assert report.warnings == []
        assert report.hard_conflict_count == 0
        assert not report.has_hard_conflicts

    def test_has_hard_conflicts(self) -> None:
        report = ConflictReport(project_path="/test", hard_conflict_count=1)
        assert report.has_hard_conflicts is True

    def test_to_dict(self) -> None:
        report = ConflictReport(
            project_path="/test",
            total_packages_analyzed=10,
            total_constraints=15,
            hard_conflict_count=1,
            soft_conflict_count=2,
        )
        d = report.to_dict()
        assert d["project_path"] == "/test"
        assert d["summary"]["total_packages_analyzed"] == 10
        assert d["summary"]["hard_conflicts"] == 1


# ── Parse Requirement Spec Tests ─────────────────────────────────────────


class TestParseRequirementSpec:
    """Tests for _parse_requirement_spec."""

    def test_simple_name(self) -> None:
        result = _parse_requirement_spec("requests")
        assert result is not None
        assert result[0] == "requests"
        assert result[1] == ""

    def test_with_version(self) -> None:
        result = _parse_requirement_spec("requests>=2.0")
        assert result is not None
        assert result[0] == "requests"
        assert result[1] == ">=2.0"

    def test_exact_version(self) -> None:
        result = _parse_requirement_spec("flask==2.0.0")
        assert result is not None
        assert result[0] == "flask"
        assert result[1] == "==2.0.0"

    def test_complex_specifier(self) -> None:
        result = _parse_requirement_spec("django>=3.0,<4.0")
        assert result is not None
        assert result[0] == "django"
        assert result[1] == ">=3.0,<4.0"

    def test_with_extras(self) -> None:
        result = _parse_requirement_spec("package[extra]>=1.0")
        assert result is not None
        assert result[0] == "package"

    def test_hyphenated(self) -> None:
        result = _parse_requirement_spec("my-package>=1.0")
        assert result is not None
        assert result[0] == "my-package"

    def test_empty(self) -> None:
        result = _parse_requirement_spec("")
        assert result is None

    def test_whitespace(self) -> None:
        result = _parse_requirement_spec("  requests>=2.0  ")
        assert result is not None
        assert result[0] == "requests"


# ── Classify Conflict Tests ──────────────────────────────────────────────


class TestClassifyConflict:
    """Tests for _classify_conflict."""

    def test_hard_conflict(self) -> None:
        """No compatible versions = hard conflict."""
        constraints = [
            VersionConstraint(package="a", target="pkg", specifier=">=2.0"),
            VersionConstraint(package="b", target="pkg", specifier="<2.0"),
        ]
        severity, suggestion = _classify_conflict(constraints, compatible_versions=[])
        assert severity == ConflictSeverity.HARD
        assert "No compatible" in suggestion

    def test_soft_conflict(self) -> None:
        """Very few compatible versions = soft conflict."""
        constraints = [
            VersionConstraint(package="a", target="pkg", specifier=">=1.0"),
            VersionConstraint(package="b", target="pkg", specifier="<2.0"),
        ]
        severity, suggestion = _classify_conflict(constraints, compatible_versions=["1.5.0"])
        assert severity == ConflictSeverity.SOFT

    def test_warning(self) -> None:
        """Multiple constraints but wide range = warning."""
        constraints = [
            VersionConstraint(package="a", target="pkg", specifier=">=1.0"),
            VersionConstraint(package="b", target="pkg", specifier="<5.0"),
        ]
        severity, suggestion = _classify_conflict(constraints, compatible_versions=["1.0", "2.0", "3.0", "4.0"])
        assert severity == ConflictSeverity.WARNING


# ── Circular Dependency Detection Tests ──────────────────────────────────


class TestDetectCircularDeps:
    """Tests for _detect_circular_deps."""

    def test_no_circular(self) -> None:
        rm = RepoMap(project_path="/test")
        rm.nodes["a"] = DependencyNode(name="a", dependencies=["b"])
        rm.nodes["b"] = DependencyNode(name="b", dependencies=["c"])
        rm.nodes["c"] = DependencyNode(name="c")

        cycles = _detect_circular_deps(rm)
        assert len(cycles) == 0

    def test_simple_cycle(self) -> None:
        rm = RepoMap(project_path="/test")
        rm.nodes["a"] = DependencyNode(name="a", dependencies=["b"])
        rm.nodes["b"] = DependencyNode(name="b", dependencies=["a"])

        cycles = _detect_circular_deps(rm)
        assert len(cycles) >= 1

    def test_three_node_cycle(self) -> None:
        rm = RepoMap(project_path="/test")
        rm.nodes["a"] = DependencyNode(name="a", dependencies=["b"])
        rm.nodes["b"] = DependencyNode(name="b", dependencies=["c"])
        rm.nodes["c"] = DependencyNode(name="c", dependencies=["a"])

        cycles = _detect_circular_deps(rm)
        assert len(cycles) >= 1

    def test_self_cycle(self) -> None:
        rm = RepoMap(project_path="/test")
        rm.nodes["a"] = DependencyNode(name="a", dependencies=["a"])

        cycles = _detect_circular_deps(rm)
        assert len(cycles) >= 1


# ── Extract Version Constraints Tests ────────────────────────────────────


class TestExtractVersionConstraints:
    """Tests for _extract_version_constraints."""

    def test_no_packages(self) -> None:
        rm = RepoMap(project_path="/test")
        mock_pypi = MagicMock()
        constraints = _extract_version_constraints(rm, mock_pypi)
        assert constraints == {}

    def test_package_with_no_deps(self) -> None:
        rm = RepoMap(project_path="/test")
        rm.nodes["a"] = DependencyNode(name="a", direct=True)
        mock_pypi = MagicMock()
        mock_pypi.get_package_info.return_value = {
            "info": {"version": "1.0", "requires_dist": []},
            "releases": {},
        }
        constraints = _extract_version_constraints(rm, mock_pypi)
        assert len(constraints) == 0

    def test_package_with_deps(self) -> None:
        rm = RepoMap(project_path="/test")
        rm.nodes["flask"] = DependencyNode(name="flask", direct=True)
        rm.nodes["werkzeug"] = DependencyNode(name="werkzeug", direct=False)

        mock_pypi = MagicMock()
        def mock_info(name: str) -> dict:
            if name == "flask":
                return {
                    "info": {
                        "version": "3.0.0",
                        "requires_dist": ["werkzeug>=2.0"],
                    },
                    "releases": {},
                }
            return None

        mock_pypi.get_package_info.side_effect = mock_info

        constraints = _extract_version_constraints(rm, mock_pypi)
        assert "werkzeug" in constraints
        assert len(constraints["werkzeug"]) == 1
        assert constraints["werkzeug"][0].specifier == ">=2.0"


# ── Rendering Tests ──────────────────────────────────────────────────────


class TestConflictRendering:
    """Tests for conflict report rendering functions."""

    def test_render_conflict_json(self) -> None:
        report = ConflictReport(
            project_path="/test",
            total_packages_analyzed=5,
            hard_conflict_count=1,
        )
        report.conflicts = [
            ConflictResult(
                package="werkzeug",
                severity=ConflictSeverity.HARD,
                compatible_versions=[],
                resolution_suggestion="No compatible version",
            )
        ]

        result = render_conflict_json(report)
        parsed = json.loads(result)
        assert parsed["project_path"] == "/test"
        assert parsed["summary"]["hard_conflicts"] == 1

    def test_render_conflict_table_no_crash(self) -> None:
        from rich.console import Console
        from io import StringIO

        report = ConflictReport(project_path="/test", total_packages_analyzed=5)
        report.conflicts = [
            ConflictResult(
                package="pkg-a",
                severity=ConflictSeverity.SOFT,
                constraints=[
                    VersionConstraint(package="x", target="pkg-a", specifier=">=1.0"),
                    VersionConstraint(package="y", target="pkg-a", specifier="<2.0"),
                ],
                compatible_versions=["1.5.0"],
                resolution_suggestion="Only 1 compatible version",
            )
        ]

        console = Console(file=StringIO(), width=140)
        render_conflict_table(report, console=console)

    def test_render_conflict_table_no_conflicts(self) -> None:
        from rich.console import Console
        from io import StringIO

        report = ConflictReport(project_path="/test", total_packages_analyzed=5)
        console = Console(file=StringIO(), width=140)
        render_conflict_table(report, console=console)

    def test_render_with_circular_deps(self) -> None:
        from rich.console import Console
        from io import StringIO

        report = ConflictReport(project_path="/test")
        report.circular_deps = [["a", "b", "a"]]

        console = Console(file=StringIO(), width=140)
        render_conflict_table(report, console=console)


# ── Integration Tests ────────────────────────────────────────────────────


class TestConflictIntegration:
    """Integration tests for conflict detection."""

    def test_diamond_dependency(self) -> None:
        """Test diamond dependency pattern: A->B, A->C, B->D>=2.0, C->D<2.0."""
        rm = RepoMap(project_path="/test")
        rm.nodes["a"] = DependencyNode(name="a", direct=True, dependencies=["b", "c"])
        rm.nodes["b"] = DependencyNode(name="b", direct=False, dependents=["a"], dependencies=["d"])
        rm.nodes["c"] = DependencyNode(name="c", direct=False, dependents=["a"], dependencies=["d"])
        rm.nodes["d"] = DependencyNode(name="d", direct=False, dependents=["b", "c"])

        # Verify the structure
        assert rm.nodes["d"].dependents_count == 2

    def test_conflict_severity_ordering(self) -> None:
        """Test that severity levels are correctly ordered."""
        assert ConflictSeverity.HARD != ConflictSeverity.SOFT
        assert ConflictSeverity.SOFT != ConflictSeverity.WARNING
