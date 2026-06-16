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
                            name="urllib3",
                            version="2.0",
                            status=HealthStatus.HEALTHY,
                            depth=1,
                        ),
                        TreeNode(
                            name="certifi",
                            version="2023.7",
                            status=HealthStatus.OUTDATED,
                            depth=1,
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
                            name="shared",
                            version="1.0",
                            status=HealthStatus.HEALTHY,
                            depth=1,
                        ),
                    ],
                ),
                TreeNode(
                    name="pkg-b",
                    version="1.0",
                    status=HealthStatus.HEALTHY,
                    children=[
                        TreeNode(
                            name="shared",
                            version="1.0",
                            status=HealthStatus.HEALTHY,
                            depth=1,
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


class TestMermaidExport:
    """Tests for Mermaid diagram export."""

    def test_mermaid_basic_graph(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="requests", name="requests", version="2.31.0", status="healthy"),
                GraphNode(id="urllib3", name="urllib3", version="2.0", status="healthy"),
            ],
            links=[GraphLink(source="requests", target="urllib3")],
        )
        mermaid = graph.to_mermaid()
        assert "graph TD" in mermaid
        assert "requests" in mermaid
        assert "urllib3" in mermaid
        assert "-->" in mermaid

    def test_mermaid_with_vulnerable_package(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg-a", name="pkg-a", version="1.0", status="healthy"),
                GraphNode(
                    id="pkg-b",
                    name="pkg-b",
                    version="1.0",
                    status="vulnerable",
                    vuln_count=2,
                ),
            ],
            links=[GraphLink(source="pkg-a", target="pkg-b")],
        )
        mermaid = graph.to_mermaid()
        assert "pkg-a" in mermaid
        assert "pkg-b" in mermaid
        # Vulnerable packages should have red styling
        assert "fill:#f44336" in mermaid or "fill:#f44336" in mermaid.lower()

    def test_mermaid_with_outdated_package(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg-a", name="pkg-a", version="1.0", status="healthy"),
                GraphNode(id="pkg-b", name="pkg-b", version="1.0", status="outdated"),
            ],
            links=[GraphLink(source="pkg-a", target="pkg-b")],
        )
        mermaid = graph.to_mermaid()
        # Outdated packages should have orange/yellow styling
        assert "fill:#ff9800" in mermaid or "fill:#ff9800" in mermaid.lower()

    def test_mermaid_with_unmaintained_package(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg-a", name="pkg-a", version="1.0", status="healthy"),
                GraphNode(id="pkg-b", name="pkg-b", version="1.0", status="unmaintained"),
            ],
            links=[GraphLink(source="pkg-a", target="pkg-b")],
        )
        mermaid = graph.to_mermaid()
        # Unmaintained packages should have gray styling
        assert "fill:#9e9e9e" in mermaid or "fill:#9e9e9e" in mermaid.lower()

    def test_mermaid_with_yanked_package(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg-a", name="pkg-a", version="1.0", status="healthy"),
                GraphNode(id="pkg-b", name="pkg-b", version="1.0", status="yanked"),
            ],
            links=[GraphLink(source="pkg-a", target="pkg-b")],
        )
        mermaid = graph.to_mermaid()
        # Yanked packages should have orange-red styling
        assert "fill:#ff5722" in mermaid or "fill:#ff5722" in mermaid.lower()

    def test_mermaid_with_removed_package(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg-a", name="pkg-a", version="1.0", status="healthy"),
                GraphNode(id="pkg-b", name="pkg-b", version="1.0", status="removed"),
            ],
            links=[GraphLink(source="pkg-a", target="pkg-b")],
        )
        mermaid = graph.to_mermaid()
        # Removed packages should have dark red styling
        assert "fill:#b71c1c" in mermaid or "fill:#b71c1c" in mermaid.lower()

    def test_mermaid_with_unknown_package(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg-a", name="pkg-a", version="1.0", status="healthy"),
                GraphNode(id="pkg-b", name="pkg-b", version="1.0", status="unknown"),
            ],
            links=[GraphLink(source="pkg-a", target="pkg-b")],
        )
        mermaid = graph.to_mermaid()
        # Unknown packages should have light gray styling
        assert "fill:#bdbdbd" in mermaid or "fill:#bdbdbd" in mermaid.lower()

    def test_mermaid_sanitizes_node_names(self) -> None:
        """Node names with special chars should be sanitized for Mermaid IDs."""
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(
                    id="pkg-with-dash", name="pkg-with-dash", version="1.0", status="healthy"
                ),
                GraphNode(
                    id="pkg_with_underscore",
                    name="pkg_with_underscore",
                    version="1.0",
                    status="healthy",
                ),
                GraphNode(
                    id="pkg.with.dots", name="pkg.with.dots", version="1.0", status="healthy"
                ),
            ],
            links=[
                GraphLink(source="pkg-with-dash", target="pkg_with_underscore"),
                GraphLink(source="pkg_with_underscore", target="pkg.with.dots"),
            ],
        )
        mermaid = graph.to_mermaid()
        # Mermaid IDs should be valid (alphanumeric + underscore)
        assert "pkg_with_dash" in mermaid or "pkgwithdash" in mermaid
        assert "pkg_with_underscore" in mermaid
        assert "pkg_with_dots" in mermaid or "pkgwithdots" in mermaid

    def test_mermaid_empty_graph(self) -> None:
        graph = DependencyGraph(project_path="/tmp/empty")
        mermaid = graph.to_mermaid()
        assert "graph TD" in mermaid
        # Should still have valid structure even with no nodes

    def test_mermaid_multiple_roots(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="app", name="app", version="1.0", status="healthy", depth=0),
                GraphNode(id="lib-a", name="lib-a", version="1.0", status="healthy", depth=1),
                GraphNode(id="lib-b", name="lib-b", version="1.0", status="healthy", depth=1),
            ],
            links=[
                GraphLink(source="app", target="lib-a"),
                GraphLink(source="app", target="lib-b"),
            ],
        )
        mermaid = graph.to_mermaid()
        assert "app" in mermaid
        assert "lib-a" in mermaid
        assert "lib-b" in mermaid
        # Both edges from app should exist
        assert mermaid.count("app") >= 2

    def test_mermaid_shared_dependency(self) -> None:
        """Shared dependencies should appear once but have multiple incoming edges."""
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg-a", name="pkg-a", version="1.0", status="healthy"),
                GraphNode(id="pkg-b", name="pkg-b", version="1.0", status="healthy"),
                GraphNode(id="shared", name="shared", version="1.0", status="healthy"),
            ],
            links=[
                GraphLink(source="pkg-a", target="shared"),
                GraphLink(source="pkg-b", target="shared"),
            ],
        )
        mermaid = graph.to_mermaid()
        # "shared" node should be defined once (one node definition)
        # Count node definitions (lines with [label] pattern for shared)
        shared_node_defs = mermaid.count('shared["shared 1.0"]')
        assert shared_node_defs == 1, (
            f"Expected 1 node definition for shared, got {shared_node_defs}"
        )
        # But both edges should be present
        assert "pkg_a --> shared" in mermaid
        assert "pkg_b --> shared" in mermaid

    def test_mermaid_includes_version_in_label(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="requests", name="requests", version="2.31.0", status="healthy"),
            ],
            links=[],
        )
        mermaid = graph.to_mermaid()
        # Version should appear in node label
        assert "2.31.0" in mermaid

    def test_mermaid_without_version(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="requests", name="requests", version=None, status="healthy"),
            ],
            links=[],
        )
        mermaid = graph.to_mermaid()
        assert "requests" in mermaid
        # Should not show "None" or "null"

    def test_mermaid_vuln_count_indicated(self) -> None:
        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="pkg", name="pkg", version="1.0", status="vulnerable", vuln_count=3),
            ],
            links=[],
        )
        mermaid = graph.to_mermaid()
        # Vulnerability count could be in label or tooltip
        assert "3" in mermaid or "vuln" in mermaid.lower()

    def test_render_mermaid_cli_integration(self) -> None:
        """Integration test for CLI --format mermaid option."""
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmpdir:
            project_dir = Path(tmpdir) / "project"
            project_dir.mkdir()
            (project_dir / "requirements.txt").write_text("requests==2.31.0\n")

            # Change to tmpdir so the default output file writes there
            import os

            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                result = runner.invoke(main, ["graph", str(project_dir), "--format", "mermaid"])
                assert result.exit_code == 0
                # Check the output file was created
                output_file = Path(tmpdir) / "depcheck-graph.mmd"
                assert output_file.exists()
                content = output_file.read_text()
                assert "graph TD" in content
                assert "requests" in content
            finally:
                os.chdir(old_cwd)

    def test_write_mermaid_to_file(self) -> None:
        """Test writing Mermaid output to a file."""
        from depcheck.graph import write_graph_mermaid

        graph = DependencyGraph(
            project_path="/tmp/project",
            nodes=[
                GraphNode(id="requests", name="requests", version="2.31.0", status="healthy"),
            ],
            links=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "graph.mmd"
            write_graph_mermaid(graph, output_path)
            assert output_path.exists()
            content = output_path.read_text()
            assert "graph TD" in content
            assert "requests" in content
