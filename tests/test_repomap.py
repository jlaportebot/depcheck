"""Tests for depcheck.repomap — dependency map, impact analysis, and reverse deps."""

from __future__ import annotations

import json
import pytest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass

from depcheck.repomap import (
    DependencyNode,
    ImpactReport,
    RepoMap,
    _calculate_metrics,
    _extract_package_name,
    _parse_project_deps,
    build_repomap,
    render_impact_json,
    render_impact_table,
    render_repomap_json,
    render_repomap_table,
    render_repomap_tree,
)
from depcheck.models import ParsedDependency


# ── DependencyNode Tests ─────────────────────────────────────────────────


class TestDependencyNode:
    """Tests for the DependencyNode dataclass."""

    def test_defaults(self) -> None:
        node = DependencyNode(name="requests")
        assert node.name == "requests"
        assert node.version is None
        assert node.direct is False
        assert node.depth == 0
        assert node.dependents == []
        assert node.dependencies == []
        assert node.is_orphan is True
        assert node.dependents_count == 0
        assert node.dependencies_count == 0

    def test_is_orphan_true(self) -> None:
        node = DependencyNode(name="orphan-pkg", dependents=[])
        assert node.is_orphan is True

    def test_is_orphan_false(self) -> None:
        node = DependencyNode(name="pop-pkg", dependents=["pkg-a", "pkg-b"])
        assert node.is_orphan is False

    def test_dependents_count(self) -> None:
        node = DependencyNode(name="pop-pkg", dependents=["a", "b", "c"])
        assert node.dependents_count == 3

    def test_dependencies_count(self) -> None:
        node = DependencyNode(name="pkg", dependencies=["x", "y"])
        assert node.dependencies_count == 2

    def test_to_dict(self) -> None:
        node = DependencyNode(
            name="requests",
            version="2.31.0",
            direct=True,
            depth=0,
            dependents=["myapp"],
            dependencies=["urllib3", "certifi"],
        )
        d = node.to_dict()
        assert d["name"] == "requests"
        assert d["version"] == "2.31.0"
        assert d["direct"] is True
        assert d["depth"] == 0
        assert d["dependents"] == ["myapp"]
        assert d["dependencies"] == ["urllib3", "certifi"]
        assert d["is_orphan"] is False


# ── ImpactReport Tests ───────────────────────────────────────────────────


class TestImpactReport:
    """Tests for the ImpactReport dataclass."""

    def test_defaults(self) -> None:
        report = ImpactReport(package="test")
        assert report.package == "test"
        assert report.removed_directly == []
        assert report.removed_transitively == []
        assert report.affected_packages == []
        assert report.total_impact == 0

    def test_total_impact(self) -> None:
        report = ImpactReport(
            package="test",
            removed_directly=["a", "b"],
            removed_transitively=["c"],
            affected_packages=["d"],
        )
        assert report.total_impact == 4

    def test_to_dict(self) -> None:
        report = ImpactReport(
            package="requests",
            removed_directly=["myapp"],
            affected_packages=["orphan-lib"],
        )
        d = report.to_dict()
        assert d["package"] == "requests"
        assert d["total_impact"] == 2


# ── RepoMap Tests ────────────────────────────────────────────────────────


class TestRepoMap:
    """Tests for the RepoMap dataclass and methods."""

    def _make_map(self) -> RepoMap:
        """Create a test repo map with known structure.

        Structure:
        app -> requests -> urllib3, certifi
        app -> flask -> werkzeug, jinja2
        flask -> jinja2 (shared dep)
        """
        rm = RepoMap(project_path="/test/project")

        # Direct deps
        rm.nodes["requests"] = DependencyNode(
            name="requests", version="2.31.0", direct=True, depth=0,
            dependencies=["urllib3", "certifi"],
        )
        rm.nodes["flask"] = DependencyNode(
            name="flask", version="3.0.0", direct=True, depth=0,
            dependencies=["werkzeug", "jinja2"],
        )

        # Transitive deps
        rm.nodes["urllib3"] = DependencyNode(
            name="urllib3", version="2.0.0", direct=False, depth=1,
            dependents=["requests"],
        )
        rm.nodes["certifi"] = DependencyNode(
            name="certifi", version="2023.7.22", direct=False, depth=1,
            dependents=["requests"],
        )
        rm.nodes["werkzeug"] = DependencyNode(
            name="werkzeug", version="3.0.0", direct=False, depth=1,
            dependents=["flask"],
        )
        rm.nodes["jinja2"] = DependencyNode(
            name="jinja2", version="3.1.2", direct=False, depth=1,
            dependents=["flask"],
            dependencies=["markupsafe"],
        )
        rm.nodes["markupsafe"] = DependencyNode(
            name="markupsafe", version="2.1.3", direct=False, depth=2,
            dependents=["jinja2"],
        )

        rm.direct_dependencies = ["requests", "flask"]
        return rm

    def test_get_node(self) -> None:
        rm = self._make_map()
        node = rm.get_node("requests")
        assert node is not None
        assert node.version == "2.31.0"

    def test_get_node_normalized(self) -> None:
        rm = self._make_map()
        # Should work with different casing/hyphens
        node = rm.get_node("Jinja2")
        assert node is not None

    def test_get_node_missing(self) -> None:
        rm = self._make_map()
        node = rm.get_node("nonexistent")
        assert node is None

    def test_impact_analysis_direct(self) -> None:
        rm = self._make_map()
        # Removing requests affects urllib3 and certifi (they depend on requests)
        impact = rm.impact_analysis("requests")
        assert "urllib3" in impact.affected_packages or "certifi" in impact.affected_packages

    def test_impact_analysis_missing_pkg(self) -> None:
        rm = self._make_map()
        impact = rm.impact_analysis("nonexistent")
        assert impact.total_impact == 0

    def test_impact_analysis_orphan(self) -> None:
        rm = self._make_map()
        # Removing markupsafe: jinja2 depends on it, markupsafe depends on nothing
        impact = rm.impact_analysis("markupsafe")
        # jinja2 directly depends on markupsafe
        assert "jinja2" in impact.removed_directly

    def test_top_dependents(self) -> None:
        rm = self._make_map()
        top = rm.top_dependents(limit=3)
        assert len(top) <= 3
        # The most depended-upon should have the highest count
        if len(top) > 1:
            assert top[0][1] >= top[1][1]

    def test_to_dict(self) -> None:
        rm = self._make_map()
        d = rm.to_dict()
        assert d["project_path"] == "/test/project"
        assert "nodes" in d
        assert "requests" in d["nodes"]


# ── Helper Function Tests ────────────────────────────────────────────────


class TestExtractPackageName:
    """Tests for _extract_package_name."""

    def test_simple_name(self) -> None:
        assert _extract_package_name("requests") == "requests"

    def test_version_specifier(self) -> None:
        assert _extract_package_name("requests>=2.0") == "requests"

    def test_exact_version(self) -> None:
        assert _extract_package_name("flask==2.0.0") == "flask"

    def test_with_extras(self) -> None:
        assert _extract_package_name("package[extra]>=1.0") == "package"

    def test_compatible_release(self) -> None:
        assert _extract_package_name("django~=4.0") == "django"

    def test_complex_specifier(self) -> None:
        assert _extract_package_name("my-package>=1.0,<2.0") == "my-package"

    def test_invalid_input(self) -> None:
        assert _extract_package_name("") is None
        assert _extract_package_name("   ") is None

    def test_hyphenated_name(self) -> None:
        assert _extract_package_name("my-package>=1.0") == "my-package"

    def test_dotted_name(self) -> None:
        assert _extract_package_name("zope.interface>=5.0") == "zope.interface"


class TestCalculateMetrics:
    """Tests for _calculate_metrics."""

    def test_basic_metrics(self) -> None:
        rm = RepoMap(project_path="/test")
        rm.nodes["a"] = DependencyNode(name="a", direct=True, depth=0)
        rm.nodes["b"] = DependencyNode(name="b", direct=False, depth=1, dependents=["a"])
        rm.nodes["c"] = DependencyNode(name="c", direct=False, depth=2)
        rm.nodes["d"] = DependencyNode(name="d", direct=False, depth=1, dependents=["a"])

        _calculate_metrics(rm)

        assert rm.total_packages == 4
        assert rm.max_depth == 2
        # "c" is an orphan (no dependents, not direct)
        assert "c" in rm.orphan_packages

    def test_empty_map(self) -> None:
        rm = RepoMap(project_path="/test")
        _calculate_metrics(rm)
        assert rm.total_packages == 0
        assert rm.max_depth == 0


# ── Build RepoMap Tests (with mocking) ───────────────────────────────────


class TestBuildRepomap:
    """Tests for build_repomap with mocked PyPI."""

    @patch("depcheck.repomap.PyPIClient")
    @patch("depcheck.repomap._parse_project_deps")
    def test_build_basic_map(self, mock_parse: MagicMock, mock_pypi_cls: MagicMock) -> None:
        """Test building a basic repo map."""
        mock_parse.return_value = [
            ParsedDependency(name="requests", version="2.31.0"),
            ParsedDependency(name="flask", version="3.0.0"),
        ]

        mock_client = MagicMock()
        mock_pypi_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_pypi_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.resolve_version.side_effect = lambda dep: dep.version
        mock_client.get_package_info.return_value = None  # No transitive deps

        rm = build_repomap("/fake/project", resolve_depth=0)

        assert "requests" in rm.nodes
        assert "flask" in rm.nodes
        assert rm.direct_dependencies == ["requests", "flask"]

    @patch("depcheck.repomap.PyPIClient")
    @patch("depcheck.repomap._parse_project_deps")
    def test_build_with_transitive(self, mock_parse: MagicMock, mock_pypi_cls: MagicMock) -> None:
        """Test building a repo map with transitive dependency resolution."""
        mock_parse.return_value = [
            ParsedDependency(name="requests", version="2.31.0"),
        ]

        mock_client = MagicMock()
        mock_pypi_cls.return_value.__enter__ = MagicMock(return_value=mock_client)
        mock_pypi_cls.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.resolve_version.side_effect = lambda dep: dep.version

        # requests depends on urllib3 and certifi
        def mock_info(name: str) -> dict:
            if name == "requests":
                return {
                    "info": {"version": "2.31.0"},
                    "releases": {},
                    "info_detail": {},
                    "info": {
                        "version": "2.31.0",
                        "requires_dist": [
                            "urllib3>=1.21.1",
                            "certifi>=2017.4.17",
                        ],
                    },
                }
            return None

        mock_client.get_package_info.side_effect = mock_info

        rm = build_repomap("/fake/project", resolve_depth=1)

        assert "requests" in rm.nodes
        # Check that transitive deps were added
        req_node = rm.nodes["requests"]
        assert "urllib3" in req_node.dependencies or "certifi" in req_node.dependencies


# ── Rendering Tests ──────────────────────────────────────────────────────


class TestRendering:
    """Tests for rendering functions."""

    def test_render_repomap_json(self) -> None:
        rm = RepoMap(project_path="/test", total_packages=2, max_depth=1)
        rm.nodes["a"] = DependencyNode(name="a", direct=True, depth=0)
        rm.nodes["b"] = DependencyNode(name="b", direct=False, depth=1, dependents=["a"])

        result = render_repomap_json(rm)
        parsed = json.loads(result)
        assert parsed["project_path"] == "/test"
        assert parsed["total_packages"] == 2

    def test_render_impact_json(self) -> None:
        impact = ImpactReport(
            package="requests",
            removed_directly=["myapp"],
            affected_packages=["orphan-lib"],
        )
        result = render_impact_json(impact)
        parsed = json.loads(result)
        assert parsed["package"] == "requests"
        assert parsed["total_impact"] == 2

    def test_render_repomap_table_no_crash(self) -> None:
        """Test that render_repomap_table doesn't crash."""
        from io import StringIO
        from rich.console import Console

        rm = RepoMap(project_path="/test", total_packages=1, max_depth=0)
        rm.nodes["a"] = DependencyNode(name="a", version="1.0", direct=True, depth=0)
        rm.direct_dependencies = ["a"]

        console = Console(file=StringIO(), width=120)
        render_repomap_table(rm, console=console)
        # Should produce output
        output = console.file.getvalue()
        assert len(output) > 0

    def test_render_repomap_tree_no_crash(self) -> None:
        """Test that render_repomap_tree doesn't crash."""
        from io import StringIO
        from rich.console import Console

        rm = RepoMap(project_path="/test", total_packages=1, max_depth=0)
        rm.nodes["a"] = DependencyNode(name="a", version="1.0", direct=True, depth=0)
        rm.direct_dependencies = ["a"]

        console = Console(file=StringIO(), width=120)
        render_repomap_tree(rm, console=console)
        output = console.file.getvalue()
        assert len(output) > 0

    def test_render_impact_table_no_crash(self) -> None:
        """Test that render_impact_table doesn't crash."""
        from io import StringIO
        from rich.console import Console

        impact = ImpactReport(
            package="test-pkg",
            removed_directly=["dep1"],
            removed_transitively=["dep2"],
            affected_packages=["dep3"],
        )

        console = Console(file=StringIO(), width=120)
        render_impact_table(impact, console=console)
        output = console.file.getvalue()
        assert len(output) > 0

    def test_render_impact_table_no_impact(self) -> None:
        """Test rendering impact table with zero impact."""
        from io import StringIO
        from rich.console import Console

        impact = ImpactReport(package="safe-pkg")

        console = Console(file=StringIO(), width=120)
        render_impact_table(impact, console=console)
        output = console.file.getvalue()
        assert "No packages" in output or "affected" in output.lower()


# ── Integration Tests ────────────────────────────────────────────────────


class TestRepoMapIntegration:
    """Integration tests for repo map features."""

    def test_impact_chain(self) -> None:
        """Test impact analysis through a dependency chain."""
        rm = RepoMap(project_path="/test")
        # a -> b -> c -> d
        rm.nodes["a"] = DependencyNode(name="a", direct=True, dependencies=["b"])
        rm.nodes["b"] = DependencyNode(name="b", dependents=["a"], dependencies=["c"])
        rm.nodes["c"] = DependencyNode(name="c", dependents=["b"], dependencies=["d"])
        rm.nodes["d"] = DependencyNode(name="d", dependents=["c"])

        # Impact of removing "b"
        impact = rm.impact_analysis("b")
        assert "a" in impact.removed_directly  # a depends on b
        # c's dependents are b (which is being removed), so c might be in transitive

    def test_shared_dependency_impact(self) -> None:
        """Test impact analysis with a shared dependency."""
        rm = RepoMap(project_path="/test")
        # Both flask and requests depend on urllib3
        rm.nodes["flask"] = DependencyNode(name="flask", direct=True)
        rm.nodes["requests"] = DependencyNode(name="requests", direct=True, dependencies=["urllib3"])
        rm.nodes["urllib3"] = DependencyNode(name="urllib3", dependents=["requests"])

        # Removing urllib3 only directly affects requests
        impact = rm.impact_analysis("urllib3")
        assert "requests" in impact.removed_directly

    def test_orphan_detection(self) -> None:
        """Test orphan package detection."""
        rm = RepoMap(project_path="/test")
        rm.nodes["direct-pkg"] = DependencyNode(name="direct-pkg", direct=True, depth=0)
        rm.nodes["used-transitive"] = DependencyNode(
            name="used-transitive", direct=False, depth=1, dependents=["direct-pkg"]
        )
        rm.nodes["orphan-transitive"] = DependencyNode(
            name="orphan-transitive", direct=False, depth=1
        )

        _calculate_metrics(rm)
        assert "orphan-transitive" in rm.orphan_packages
        assert "used-transitive" not in rm.orphan_packages
        # Direct deps are not considered orphans
        assert "direct-pkg" not in rm.orphan_packages

    def test_circular_reference_impact(self) -> None:
        """Test impact analysis with circular dependencies."""
        rm = RepoMap(project_path="/test")
        # a -> b -> a (circular)
        rm.nodes["a"] = DependencyNode(name="a", direct=True, dependencies=["b"])
        rm.nodes["b"] = DependencyNode(name="b", dependents=["a"], dependencies=["a"])

        # Should not infinite loop
        impact = rm.impact_analysis("a")
        assert impact is not None
        # b depends on a, so b would be affected
        assert "b" in impact.affected_packages
