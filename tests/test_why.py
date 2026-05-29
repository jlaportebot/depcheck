"""Tests for depcheck why — dependency chain analysis."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from depcheck.models import HealthStatus, ParsedDependency
from depcheck.why import (
    DependencyChain,
    WhyResult,
    _build_adjacency_map,
    _find_all_paths,
    render_why_json,
    render_why_table,
    resolve_why,
)


class TestDependencyChain:
    """Tests for the DependencyChain dataclass."""

    def test_empty_chain(self) -> None:
        chain = DependencyChain()
        assert chain.total_links == -1  # no elements
        assert chain.target is None
        assert chain.root is None

    def test_single_hop_direct(self) -> None:
        chain = DependencyChain(
            path=[("requests", "2.31.0", HealthStatus.HEALTHY)],
            is_direct=True,
        )
        assert chain.total_links == 0
        assert chain.is_direct is True
        assert chain.target == ("requests", "2.31.0", HealthStatus.HEALTHY)
        assert chain.root == ("requests", "2.31.0", HealthStatus.HEALTHY)

    def test_multi_hop_chain(self) -> None:
        chain = DependencyChain(
            path=[
                ("requests", "2.31.0", HealthStatus.HEALTHY),
                ("urllib3", "2.0.7", HealthStatus.OUTDATED),
                ("certifi", "2023.7.22", HealthStatus.VULNERABLE),
            ],
        )
        assert chain.total_links == 2
        assert chain.is_direct is False
        assert chain.target == ("certifi", "2023.7.22", HealthStatus.VULNERABLE)
        assert chain.root == ("requests", "2.31.0", HealthStatus.HEALTHY)

    def test_to_dict(self) -> None:
        chain = DependencyChain(
            path=[
                ("requests", "2.31.0", HealthStatus.HEALTHY),
                ("urllib3", "2.0.7", HealthStatus.OUTDATED),
            ],
            is_direct=False,
        )
        d = chain.to_dict()
        assert d["is_direct"] is False
        assert d["total_links"] == 1
        assert len(d["path"]) == 2
        assert d["path"][0]["name"] == "requests"
        assert d["path"][0]["status"] == "healthy"
        assert d["path"][1]["name"] == "urllib3"
        assert d["path"][1]["status"] == "outdated"


class TestWhyResult:
    """Tests for the WhyResult dataclass."""

    def test_not_found_result(self) -> None:
        result = WhyResult(target="nonexistent", found=False)
        assert result.found is False
        assert result.chains == []

    def test_to_dict(self) -> None:
        result = WhyResult(
            target="certifi",
            found=True,
            is_direct=False,
            chains=[
                DependencyChain(
                    path=[
                        ("requests", "2.31.0", HealthStatus.HEALTHY),
                        ("urllib3", "2.0.7", HealthStatus.OUTDATED),
                        ("certifi", "2023.7.22", HealthStatus.HEALTHY),
                    ],
                )
            ],
            direct_deps=["requests", "click"],
            project_path="/tmp/myproject",
        )
        d = result.to_dict()
        assert d["target"] == "certifi"
        assert d["found"] is True
        assert d["is_direct"] is False
        assert d["project_path"] == "/tmp/myproject"
        assert len(d["chains"]) == 1
        assert d["chains"][0]["total_links"] == 2


class TestFindAllPaths:
    """Tests for the _find_all_paths DFS algorithm."""

    def test_direct_connection(self) -> None:
        adj = {"a": ["b"], "b": ["c"], "c": []}
        paths = _find_all_paths(adj, "a", "b")
        assert len(paths) == 1
        assert paths[0] == ["a", "b"]

    def test_two_hop_path(self) -> None:
        adj = {"a": ["b"], "b": ["c"], "c": []}
        paths = _find_all_paths(adj, "a", "c")
        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_multiple_paths(self) -> None:
        adj = {
            "a": ["b", "d"],
            "b": ["c"],
            "d": ["c"],
            "c": [],
        }
        paths = _find_all_paths(adj, "a", "c")
        assert len(paths) == 2
        # Shortest first
        assert ["a", "b", "c"] in paths
        assert ["a", "d", "c"] in paths

    def test_no_path(self) -> None:
        adj = {"a": ["b"], "b": [], "c": []}
        paths = _find_all_paths(adj, "a", "c")
        assert paths == []

    def test_cycle_detection(self) -> None:
        adj = {
            "a": ["b"],
            "b": ["c"],
            "c": ["a"],  # cycle back to a
        }
        paths = _find_all_paths(adj, "a", "c")
        assert len(paths) == 1
        assert paths[0] == ["a", "b", "c"]

    def test_max_paths_limit(self) -> None:
        adj = {}
        # Create a graph with many paths to target
        for i in range(10):
            adj[f"mid{i}"] = ["target"]
        adj["root"] = [f"mid{i}" for i in range(10)]
        adj["target"] = []

        paths = _find_all_paths(adj, "root", "target", max_paths=3)
        assert len(paths) <= 3

    def test_max_depth(self) -> None:
        adj = {
            "a": ["b"],
            "b": ["c"],
            "c": ["d"],
            "d": ["target"],
            "target": [],
        }
        # With max_depth=2, should not find a 4-hop path
        paths = _find_all_paths(adj, "a", "target", max_depth=2)
        assert paths == []


class TestBuildAdjacencyMap:
    """Tests for the _build_adjacency_map function."""

    def test_simple_graph(self) -> None:
        mock_pypi = MagicMock()
        mock_osv = MagicMock()

        # Mock PyPI responses
        requests_info = {
            "info": {
                "version": "2.31.0",
                "requires_dist": ["urllib3>=1.21.1,<3", "certifi>=2017.4.17"],
            },
            "releases": {},
        }
        urllib3_info = {
            "info": {"version": "2.0.7", "requires_dist": []},
            "releases": {},
        }
        certifi_info = {
            "info": {"version": "2023.7.22", "requires_dist": []},
            "releases": {},
        }

        mock_pypi.get_package_info.side_effect = lambda name: {
            "requests": requests_info,
            "urllib3": urllib3_info,
            "certifi": certifi_info,
        }.get(name)
        mock_pypi.resolve_version.side_effect = lambda dep, info=None: (
            info.get("info", {}).get("version") if info else None
        )

        deps = [ParsedDependency(name="requests", version="2.31.0")]
        adj, versions, statuses, errors = _build_adjacency_map(
            deps, mock_pypi, mock_osv, max_depth=2, check_vulnerabilities=False
        )

        assert "requests" in adj
        assert "urllib3" in adj["requests"]
        assert "certifi" in adj["requests"]


class TestResolveWhy:
    """Tests for the resolve_why function."""

    def test_invalid_path(self, tmp_path) -> None:
        result = resolve_why("/nonexistent/path", "requests")
        assert result.found is False
        assert len(result.errors) > 0

    def test_no_dependencies(self, tmp_path) -> None:
        # Create empty project directory
        project = tmp_path / "empty_project"
        project.mkdir()
        result = resolve_why(str(project), "requests")
        assert result.found is False
        assert "No dependencies found" in result.errors[0]

    @patch("depcheck.why.PyPIClient")
    @patch("depcheck.why.OSVClient")
    def test_direct_dependency(self, mock_osv_cls, mock_pypi_cls, tmp_path) -> None:
        """Test that a direct dependency is correctly identified."""
        # Create project with requirements.txt
        project = tmp_path / "direct_project"
        project.mkdir()
        (project / "requirements.txt").write_text("requests==2.31.0\n")

        mock_pypi = MagicMock()
        mock_osv = MagicMock()
        mock_pypi_cls.return_value.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        requests_info = {
            "info": {"version": "2.31.0", "requires_dist": ["urllib3>=1.21.1"]},
            "releases": {},
        }
        urllib3_info = {
            "info": {"version": "2.0.7", "requires_dist": []},
            "releases": {},
        }

        mock_pypi.get_package_info.side_effect = lambda name: {
            "requests": requests_info,
            "urllib3": urllib3_info,
        }.get(name)
        mock_pypi.resolve_version.side_effect = lambda dep, info=None: (
            info.get("info", {}).get("version") if info else dep.version
        )

        # Make check_package_health return healthy
        with patch("depcheck.why.check_package_health") as mock_check:
            mock_pkg = MagicMock()
            mock_pkg.status = HealthStatus.HEALTHY
            mock_check.return_value = mock_pkg

            result = resolve_why(str(project), "requests", check_vulnerabilities=False)

        assert result.found is True
        assert result.is_direct is True

    @patch("depcheck.why.PyPIClient")
    @patch("depcheck.why.OSVClient")
    def test_transitive_dependency(self, mock_osv_cls, mock_pypi_cls, tmp_path) -> None:
        """Test finding a transitive dependency through the chain."""
        project = tmp_path / "transitive_project"
        project.mkdir()
        (project / "requirements.txt").write_text("requests==2.31.0\n")

        mock_pypi = MagicMock()
        mock_osv = MagicMock()
        mock_pypi_cls.return_value.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        requests_info = {
            "info": {
                "version": "2.31.0",
                "requires_dist": ["urllib3>=1.21.1,<3", "certifi>=2017.4.17"],
            },
            "releases": {},
        }
        urllib3_info = {
            "info": {"version": "2.0.7", "requires_dist": []},
            "releases": {},
        }
        certifi_info = {
            "info": {"version": "2023.7.22", "requires_dist": []},
            "releases": {},
        }

        mock_pypi.get_package_info.side_effect = lambda name: {
            "requests": requests_info,
            "urllib3": urllib3_info,
            "certifi": certifi_info,
        }.get(name)
        mock_pypi.resolve_version.side_effect = lambda dep, info=None: (
            info.get("info", {}).get("version") if info else dep.version
        )

        with patch("depcheck.why.check_package_health") as mock_check:
            mock_pkg = MagicMock()
            mock_pkg.status = HealthStatus.HEALTHY
            mock_check.return_value = mock_pkg

            result = resolve_why(str(project), "certifi", check_vulnerabilities=False)

        assert result.found is True
        assert result.is_direct is False
        # Should have at least one chain: requests -> certifi
        assert len(result.chains) >= 1

    @patch("depcheck.why.PyPIClient")
    @patch("depcheck.why.OSVClient")
    def test_package_not_found(self, mock_osv_cls, mock_pypi_cls, tmp_path) -> None:
        """Test that a non-existent package returns found=False."""
        project = tmp_path / "notfound_project"
        project.mkdir()
        (project / "requirements.txt").write_text("requests==2.31.0\n")

        mock_pypi = MagicMock()
        mock_osv = MagicMock()
        mock_pypi_cls.return_value.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi_cls.return_value.__exit__ = MagicMock(return_value=False)
        mock_osv_cls.return_value.__enter__ = MagicMock(return_value=mock_osv)
        mock_osv_cls.return_value.__exit__ = MagicMock(return_value=False)

        requests_info = {
            "info": {"version": "2.31.0", "requires_dist": []},
            "releases": {},
        }

        mock_pypi.get_package_info.side_effect = lambda name: {
            "requests": requests_info,
        }.get(name)
        mock_pypi.resolve_version.side_effect = lambda dep, info=None: (
            info.get("info", {}).get("version") if info else dep.version
        )

        with patch("depcheck.why.check_package_health") as mock_check:
            mock_pkg = MagicMock()
            mock_pkg.status = HealthStatus.HEALTHY
            mock_check.return_value = mock_pkg

            result = resolve_why(str(project), "nonexistent-pkg", check_vulnerabilities=False)

        assert result.found is False


class TestRenderWhyTable:
    """Tests for the Rich table rendering."""

    def test_not_found_render(self) -> None:
        from io import StringIO

        from rich.console import Console

        result = WhyResult(target="nonexistent", found=False, project_path="/tmp/test")
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_why_table(result, console=console)
        output = buf.getvalue()
        assert "nonexistent" in output
        assert "not found" in output.lower()

    def test_direct_dep_render(self) -> None:
        from io import StringIO

        from rich.console import Console

        result = WhyResult(
            target="requests",
            found=True,
            is_direct=True,
            chains=[
                DependencyChain(
                    path=[("requests", "2.31.0", HealthStatus.HEALTHY)],
                    is_direct=True,
                )
            ],
            direct_deps=["requests"],
            project_path="/tmp/test",
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_why_table(result, console=console)
        output = buf.getvalue()
        assert "requests" in output
        assert "direct" in output.lower()

    def test_chain_render(self) -> None:
        from io import StringIO

        from rich.console import Console

        result = WhyResult(
            target="certifi",
            found=True,
            is_direct=False,
            chains=[
                DependencyChain(
                    path=[
                        ("requests", "2.31.0", HealthStatus.HEALTHY),
                        ("certifi", "2023.7.22", HealthStatus.HEALTHY),
                    ],
                )
            ],
            direct_deps=["requests"],
            project_path="/tmp/test",
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_why_table(result, console=console)
        output = buf.getvalue()
        assert "requests" in output
        assert "certifi" in output
        assert "Chain" in output


class TestRenderWhyJson:
    """Tests for the JSON rendering."""

    def test_json_output(self) -> None:
        from io import StringIO

        from rich.console import Console

        result = WhyResult(
            target="certifi",
            found=True,
            is_direct=False,
            chains=[
                DependencyChain(
                    path=[
                        ("requests", "2.31.0", HealthStatus.HEALTHY),
                        ("certifi", "2023.7.22", HealthStatus.HEALTHY),
                    ],
                )
            ],
            direct_deps=["requests"],
            project_path="/tmp/test",
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_why_json(result, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert data["target"] == "certifi"
        assert data["found"] is True
        assert len(data["chains"]) == 1
        assert data["chains"][0]["total_links"] == 1

    def test_not_found_json(self) -> None:
        from io import StringIO

        from rich.console import Console

        result = WhyResult(target="nonexistent", found=False)
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_why_json(result, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert data["found"] is False
        assert data["chains"] == []
