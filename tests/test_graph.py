"""Tests for the dependency graph visualization module."""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

from depcheck.graph import (
    STATUS_COLORS,
    STATUS_LABELS,
    DependencyGraph,
    GraphLink,
    GraphNode,
    render_graph_html,
    tree_to_graph,
    write_graph_html,
)
from depcheck.models import HealthStatus
from depcheck.tree import DependencyTreeResult, TreeNode


class TestGraphNode:
    """Tests for GraphNode dataclass."""

    def test_to_dict_full(self) -> None:
        node = GraphNode(
            id="requests",
            name="requests",
            version="2.31.0",
            latest_version="2.32.0",
            status="outdated",
            vuln_count=0,
            license_id="Apache-2.0",
            license_category="permissive",
            is_compliant=True,
            depth=0,
        )
        d = node.to_dict()
        assert d["id"] == "requests"
        assert d["name"] == "requests"
        assert d["version"] == "2.31.0"
        assert d["latestVersion"] == "2.32.0"
        assert d["status"] == "outdated"
        assert d["vulnCount"] == 0
        assert d["license"] == "Apache-2.0"
        assert d["licenseCategory"] == "permissive"
        assert d["licenseCompliant"] is True
        assert d["depth"] == 0

    def test_to_dict_minimal(self) -> None:
        node = GraphNode(id="foo", name="foo")
        d = node.to_dict()
        assert d["id"] == "foo"
        assert d["version"] is None
        assert d["latestVersion"] is None
        assert d["license"] is None
        assert d["licenseCategory"] is None
        assert d["licenseCompliant"] is None

    def test_to_dict_vulnerable(self) -> None:
        node = GraphNode(
            id="pkg",
            name="pkg",
            version="1.0",
            status="vulnerable",
            vuln_count=3,
        )
        d = node.to_dict()
        assert d["status"] == "vulnerable"
        assert d["vulnCount"] == 3


class TestGraphLink:
    """Tests for GraphLink dataclass."""

    def test_to_dict(self) -> None:
        link = GraphLink(source="requests", target="urllib3")
        d = link.to_dict()
        assert d["source"] == "requests"
        assert d["target"] == "urllib3"


class TestDependencyGraph:
    """Tests for DependencyGraph dataclass."""

    def test_to_dict(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="requests", name="requests", version="2.31.0"),
                GraphNode(id="urllib3", name="urllib3", version="2.0"),
            ],
            links=[GraphLink(source="requests", target="urllib3")],
            files_scanned=["requirements.txt"],
            errors=[],
        )
        d = graph.to_dict()
        assert d["projectPath"] == "/tmp/project"
        assert len(d["nodes"]) == 2
        assert len(d["links"]) == 1
        assert d["filesScanned"] == ["requirements.txt"]
        assert d["errors"] == []

    def test_to_dict_empty(self) -> None:
        graph = DependencyGraph(project_path="/tmp/empty")
        d = graph.to_dict()
        assert d["nodes"] == []
        assert d["links"] == []


class TestTreeToGraph:
    """Tests for tree_to_graph conversion."""

    def test_single_root_no_children(self) -> None:
        tree = DependencyTreeResult(
            project_path="/tmp/project",
            roots=[
                TreeNode(name="requests", version="2.31.0", status=HealthStatus.HEALTHY),
            ],
        )
        graph = tree_to_graph(tree)
        assert len(graph.nodes) == 1
        assert graph.nodes[0].name == "requests"
        assert graph.nodes[0].status == "healthy"
        assert len(graph.links) == 0

    def test_tree_with_children(self) -> None:
        tree = DependencyTreeResult(
            project_path="/tmp/project",
            roots=[
                TreeNode(
                    name="requests",
                    version="2.31.0",
                    status=HealthStatus.HEALTHY,
                children=[
                    TreeNode(
                        name="urllib3", version="2.0",
                        status=HealthStatus.HEALTHY, depth=1,
                    ),
                    TreeNode(
                        name="certifi", version="2023.7",
                        status=HealthStatus.OUTDATED, depth=1,
                    ),
                ],
                ),
            ],
        )
        graph = tree_to_graph(tree)
        assert len(graph.nodes) == 3
        assert len(graph.links) == 2
        link_pairs = {(lk.source, lk.target) for lk in graph.links}
        assert ("requests", "urllib3") in link_pairs
        assert ("requests", "certifi") in link_pairs

    def test_deduplication_of_shared_deps(self) -> None:
        """Shared sub-dependencies should appear once as a node."""
        tree = DependencyTreeResult(
            project_path="/tmp/project",
            roots=[
                TreeNode(
                    name="pkg-a",
                    version="1.0",
                    status=HealthStatus.HEALTHY,
                    children=[
                        TreeNode(
                            name="shared", version="1.0",
                            status=HealthStatus.HEALTHY, depth=1,
                        ),
                    ],
                ),
                TreeNode(
                    name="pkg-b",
                    version="1.0",
                    status=HealthStatus.HEALTHY,
                    children=[
                        TreeNode(
                            name="shared", version="1.0",
                            status=HealthStatus.HEALTHY, depth=1,
                        ),
                    ],
                ),
            ],
        )
        graph = tree_to_graph(tree)
        # "shared" should only appear once in nodes
        names = [n.name for n in graph.nodes]
        assert names.count("shared") == 1
        # But there should be two links pointing to it
        assert len(graph.links) == 2

    def test_deep_tree(self) -> None:
        tree = DependencyTreeResult(
            project_path="/tmp/project",
            roots=[
                TreeNode(
                    name="app",
                    version="1.0",
                    status=HealthStatus.HEALTHY,
                    children=[
                        TreeNode(
                            name="lib-a",
                            version="1.0",
                            status=HealthStatus.HEALTHY,
                            depth=1,
                            children=[
                                TreeNode(
                                    name="lib-b",
                                    version="1.0",
                                    status=HealthStatus.VULNERABLE,
                                    depth=2,
                                ),
                            ],
                        ),
                    ],
                ),
            ],
        )
        graph = tree_to_graph(tree)
        assert len(graph.nodes) == 3
        assert len(graph.links) == 2
        vuln_nodes = [n for n in graph.nodes if n.status == "vulnerable"]
        assert len(vuln_nodes) == 1
        assert vuln_nodes[0].name == "lib-b"

    def test_preserves_metadata(self) -> None:
        tree = DependencyTreeResult(
            project_path="/tmp/project",
            files_scanned=["requirements.txt"],
            errors=["some warning"],
            roots=[
                TreeNode(
                    name="pkg",
                    version="1.0",
                    status=HealthStatus.HEALTHY,
                    license_id="MIT",
                    license_category="permissive",
                ),
            ],
        )
        graph = tree_to_graph(tree)
        assert graph.project_path == "/tmp/project"
        assert graph.files_scanned == ["requirements.txt"]
        assert graph.errors == ["some warning"]
        assert graph.nodes[0].license_id == "MIT"
        assert graph.nodes[0].license_category == "permissive"


class TestRenderGraphHtml:
    """Tests for the HTML rendering."""

    def test_renders_valid_html(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="requests", name="requests", version="2.31.0", status="healthy"),
            ],
            links=[],
        )
        html = render_graph_html(graph)
        assert "<!DOCTYPE html>" in html
        assert "depcheck" in html
        assert "D3" in html or "d3" in html

    def test_contains_graph_data(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="requests", name="requests", version="2.31.0", status="healthy"),
            ],
            links=[],
        )
        html = render_graph_html(graph)
        # The graph JSON should be embedded in the script
        assert "requests" in html
        assert "healthy" in html

    def test_contains_all_status_colors(self) -> None:
        graph = DependencyGraph(project_path="/tmp/project")
        html = render_graph_html(graph)
        for color in STATUS_COLORS.values():
            assert color in html

    def test_contains_legend(self) -> None:
        graph = DependencyGraph(project_path="/tmp/project")
        html = render_graph_html(graph)
        assert "Health Status" in html

    def test_contains_search_box(self) -> None:
        graph = DependencyGraph(project_path="/tmp/project")
        html = render_graph_html(graph)
        assert "search-box" in html
        assert "Search packages" in html

    def test_contains_export_buttons(self) -> None:
        graph = DependencyGraph(project_path="/tmp/project")
        html = render_graph_html(graph)
        assert "Export SVG" in html
        assert "Export PNG" in html

    def test_empty_graph_still_renders(self) -> None:
        graph = DependencyGraph(project_path="/tmp/empty")
        html = render_graph_html(graph)
        assert "<!DOCTYPE html>" in html
        # Should have empty nodes/links arrays
        assert '"nodes": []' in html
        assert '"links": []' in html

    def test_multiple_statuses_in_graph(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg-a", name="pkg-a", status="healthy"),
                GraphNode(id="pkg-b", name="pkg-b", status="vulnerable"),
                GraphNode(id="pkg-c", name="pkg-c", status="outdated"),
            ],
            links=[
                GraphLink(source="pkg-a", target="pkg-b"),
                GraphLink(source="pkg-a", target="pkg-c"),
            ],
        )
        html = render_graph_html(graph)
        assert "pkg-a" in html
        assert "pkg-b" in html
        assert "pkg-c" in html


class TestWriteGraphHtml:
    """Tests for write_graph_html file output."""

    @patch("depcheck.graph.resolve_dependency_tree")
    def test_writes_file(self, mock_resolve: MagicMock) -> None:
        mock_resolve.return_value = DependencyTreeResult(
            project_path="/tmp/project",
            roots=[
                TreeNode(name="requests", version="2.31.0", status=HealthStatus.HEALTHY),
            ],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            # Also need a requirements.txt for discover_dependencies
            project_dir = Path(tmpdir) / "project"
            project_dir.mkdir()
            (project_dir / "requirements.txt").write_text("requests==2.31.0\n")

            output_file = Path(tmpdir) / "graph.html"
            result = write_graph_html(
                project_path=str(project_dir),
                output_path=output_file,
            )
            assert result == output_file
            assert output_file.exists()
            content = output_file.read_text()
            assert "<!DOCTYPE html>" in content
            assert "requests" in content

    @patch("depcheck.graph.resolve_dependency_tree")
    def test_default_output_path(self, mock_resolve: MagicMock) -> None:
        mock_resolve.return_value = DependencyTreeResult(
            project_path="/tmp/project",
            roots=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / "project"
            project_dir.mkdir()
            (project_dir / "requirements.txt").write_text("requests\n")

            # Change to tmpdir so the default path writes there
            import os
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                result = write_graph_html(project_path=str(project_dir))
                assert result.name == "depcheck-graph.html"
                assert result.exists()
            finally:
                os.chdir(old_cwd)


class TestStatusColors:
    """Tests for status color mapping."""

    def test_all_statuses_have_colors(self) -> None:
        for status in HealthStatus:
            assert status.value in STATUS_COLORS

    def test_all_statuses_have_labels(self) -> None:
        for status in HealthStatus:
            assert status.value in STATUS_LABELS

    def test_colors_are_valid_css(self) -> None:
        for color in STATUS_COLORS.values():
            assert color.startswith("#"), f"Invalid CSS color: {color}"
            assert len(color) == 7, f"Expected 6-digit hex color: {color}"
