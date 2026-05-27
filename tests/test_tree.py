"""Tests for depcheck dependency tree module."""

from __future__ import annotations

import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

from rich.console import Console

from depcheck.models import HealthStatus
from depcheck.tree import (
    DependencyTreeResult,
    TreeNode,
    _flatten_tree,
    _parse_requires_dist,
    render_tree,
    render_tree_json,
    resolve_dependency_tree,
)


class TestTreeNode:
    """Tests for TreeNode data model."""

    def test_basic_creation(self) -> None:
        node = TreeNode(name="requests", version="2.31.0", status=HealthStatus.HEALTHY)
        assert node.name == "requests"
        assert node.version == "2.31.0"
        assert node.status == HealthStatus.HEALTHY
        assert node.children == []
        assert node.depth == 0

    def test_to_dict_simple(self) -> None:
        node = TreeNode(name="flask", version="3.0.0", status=HealthStatus.OUTDATED)
        d = node.to_dict()
        assert d["name"] == "flask"
        assert d["version"] == "3.0.0"
        assert d["status"] == "outdated"
        assert d["children"] == []

    def test_to_dict_with_children(self) -> None:
        child = TreeNode(name="click", version="8.1.0", status=HealthStatus.HEALTHY)
        parent = TreeNode(
            name="flask",
            version="3.0.0",
            status=HealthStatus.HEALTHY,
            children=[child],
        )
        d = parent.to_dict()
        assert len(d["children"]) == 1
        assert d["children"][0]["name"] == "click"

    def test_to_dict_with_license(self) -> None:
        node = TreeNode(
            name="requests",
            version="2.31.0",
            status=HealthStatus.HEALTHY,
            license_id="Apache-2.0",
            license_category="permissive",
            is_compliant=True,
        )
        d = node.to_dict()
        assert d["license"] == "Apache-2.0"
        assert d["license_category"] == "permissive"
        assert d["license_compliant"] is True

    def test_to_dict_no_license(self) -> None:
        node = TreeNode(name="pkg", version="1.0", status=HealthStatus.HEALTHY)
        d = node.to_dict()
        assert d["license"] is None
        assert d["license_compliant"] is None

    def test_circular_detection(self) -> None:
        node = TreeNode(
            name="pkg-a",
            version="1.0",
            parent_chain=frozenset({"pkg-a", "pkg-b"}),
        )
        assert node.is_circular is True

    def test_not_circular(self) -> None:
        node = TreeNode(name="pkg-a", version="1.0", parent_chain=frozenset({"pkg-b"}))
        assert node.is_circular is False


class TestDependencyTreeResult:
    """Tests for DependencyTreeResult data model."""

    def test_empty_result(self) -> None:
        result = DependencyTreeResult(project_path="/tmp/test")
        assert result.total_packages == 0
        assert result.max_depth == 0
        assert result.circular_deps == []
        assert result.errors == []

    def test_total_packages_counts_unique(self) -> None:
        child = TreeNode(name="click", version="8.0", status=HealthStatus.HEALTHY)
        root1 = TreeNode(
            name="flask",
            version="3.0",
            status=HealthStatus.HEALTHY,
            children=[child],
        )
        root2 = TreeNode(
            name="requests",
            version="2.0",
            status=HealthStatus.HEALTHY,
            children=[child],
        )
        result = DependencyTreeResult(project_path="/tmp/test", roots=[root1, root2])
        # click appears in both trees but should only be counted once
        assert result.total_packages == 3  # flask, requests, click

    def test_max_depth(self) -> None:
        grandchild = TreeNode(name="c", depth=2)
        child = TreeNode(name="b", depth=1, children=[grandchild])
        root = TreeNode(name="a", depth=0, children=[child])
        result = DependencyTreeResult(project_path="/tmp/test", roots=[root])
        assert result.max_depth == 3  # a(0) + b(1) + c(2) = 3 total depth

    def test_to_dict(self) -> None:
        root = TreeNode(name="requests", version="2.31.0", status=HealthStatus.HEALTHY)
        result = DependencyTreeResult(
            project_path="/tmp/test",
            roots=[root],
            files_scanned=["/tmp/test/requirements.txt"],
            circular_deps=[["pkg-a", "pkg-b"]],
            errors=["some error"],
            stats={"total_packages": 1},
        )
        d = result.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert len(d["tree"]) == 1
        assert d["circular_dependencies"] == [["pkg-a", "pkg-b"]]
        assert d["errors"] == ["some error"]
        assert d["stats"]["total_packages"] == 1


class TestParseRequiresDist:
    """Tests for requires_dist parsing."""

    def test_simple_requirement(self) -> None:
        result = _parse_requires_dist(["requests>=2.28"])
        assert len(result) == 1
        assert result[0][0] == "requests"
        assert result[0][1] == ">=2.28"

    def test_no_version_specifier(self) -> None:
        result = _parse_requires_dist(["click"])
        assert len(result) == 1
        assert result[0][0] == "click"
        assert result[0][1] is None

    def test_with_extras(self) -> None:
        result = _parse_requires_dist(["requests[security]>=2.28"])
        assert len(result) == 1
        assert result[0][0] == "requests"

    def test_skips_platform_markers(self) -> None:
        reqs = [
            'pywin32>=300; sys_platform == "win32"',
            "requests>=2.28",
        ]
        result = _parse_requires_dist(reqs)
        assert len(result) == 1
        assert result[0][0] == "requests"

    def test_skips_python_version_markers(self) -> None:
        reqs = [
            'tomli>=2.0; python_version < "3.11"',
            "click>=8.0",
        ]
        result = _parse_requires_dist(reqs)
        assert len(result) == 1
        assert result[0][0] == "click"

    def test_skips_extra_markers(self) -> None:
        reqs = [
            'pytest>=7.0; extra == "dev"',
            "requests>=2.28",
        ]
        result = _parse_requires_dist(reqs)
        assert len(result) == 1
        assert result[0][0] == "requests"

    def test_skips_platform_machine(self) -> None:
        reqs = [
            'typing-extensions; platform_machine != "aarch64"',
            "flask>=2.0",
        ]
        result = _parse_requires_dist(reqs)
        assert len(result) == 1
        assert result[0][0] == "flask"

    def test_multiple_requirements(self) -> None:
        reqs = [
            "requests>=2.28",
            "click>=8.0",
            "itsdangerous>=2.1",
        ]
        result = _parse_requires_dist(reqs)
        assert len(result) == 3

    def test_empty_list(self) -> None:
        assert _parse_requires_dist([]) == []

    def test_normalizes_names(self) -> None:
        result = _parse_requires_dist(["My_Package>=1.0"])
        assert result[0][0] == "my-package"

    def test_complex_version_specifier(self) -> None:
        result = _parse_requires_dist(["flask>=2.0,<3.0"])
        assert len(result) == 1
        assert result[0][0] == "flask"
        assert result[0][1] == ">=2.0,<3.0"


class TestFlattenTree:
    """Tests for _flatten_tree utility."""

    def test_empty(self) -> None:
        assert _flatten_tree([]) == []

    def test_single_node(self) -> None:
        node = TreeNode(name="a", version="1.0")
        flat = _flatten_tree([node])
        assert len(flat) == 1
        assert flat[0].name == "a"

    def test_nested(self) -> None:
        child = TreeNode(name="b", version="1.0")
        root = TreeNode(name="a", version="1.0", children=[child])
        flat = _flatten_tree([root])
        assert len(flat) == 2
        assert flat[0].name == "a"
        assert flat[1].name == "b"


class TestResolveDependencyTree:
    """Tests for resolve_dependency_tree (with mocked API clients)."""

    def test_nonexistent_directory(self) -> None:
        result = resolve_dependency_tree("/nonexistent/path")
        assert len(result.errors) > 0
        assert "not a directory" in result.errors[0]

    def test_empty_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = resolve_dependency_tree(tmpdir)
            assert len(result.errors) > 0
            assert "No dependencies found" in result.errors[0]

    def test_basic_tree_resolution(self) -> None:
        """Test tree resolution with mocked PyPI and OSV clients."""
        tmpdir = tempfile.mkdtemp()
        try:
            req_path = Path(tmpdir) / "requirements.txt"
            req_path.write_text("requests==2.31.0\n")

            mock_pypi_info = {
                "info": {
                    "version": "2.31.0",
                    "requires_dist": [
                        "charset-normalizer>=2",
                        "urllib3>=1.21",
                    ],
                    "license": "Apache-2.0",
                },
                "releases": {
                    "2.31.0": [
                        {
                            "upload_time_iso_8601": "2023-10-24T14:00:00Z",
                            "yanked": False,
                        }
                    ],
                },
            }

            with (
                patch("depcheck.tree.PyPIClient") as mock_pypi,
                patch("depcheck.tree.OSVClient") as mock_osv,
            ):
                pypi_instance = MagicMock()
                pypi_instance.get_package_info.return_value = mock_pypi_info
                pypi_instance.resolve_version.return_value = "2.31.0"
                pypi_instance.is_version_yanked.return_value = False
                pypi_instance.get_last_release_date.return_value = None
                mock_pypi.return_value.__enter__ = lambda s: pypi_instance
                mock_pypi.return_value.__exit__ = MagicMock(return_value=False)

                osv_instance = MagicMock()
                osv_instance.query_vulnerabilities.return_value = []
                mock_osv.return_value.__enter__ = lambda s: osv_instance
                mock_osv.return_value.__exit__ = MagicMock(return_value=False)

                result = resolve_dependency_tree(tmpdir, max_depth=1)
                assert len(result.roots) >= 1
                assert result.roots[0].name == "requests"
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)


class TestRenderTree:
    """Tests for tree rendering."""

    def test_empty_result(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)
        result = DependencyTreeResult(
            project_path="/tmp/test", errors=["No deps found"]
        )
        render_tree(result, console=console)
        output = buf.getvalue()
        assert "Error" in output

    def test_basic_tree_render(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        child = TreeNode(name="click", version="8.1.0", status=HealthStatus.HEALTHY)
        root = TreeNode(
            name="flask",
            version="3.0.0",
            status=HealthStatus.HEALTHY,
            children=[child],
        )
        result = DependencyTreeResult(project_path="/tmp/test", roots=[root])

        render_tree(result, console=console)
        output = buf.getvalue()
        assert "flask" in output
        assert "click" in output

    def test_tree_with_issues(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        root = TreeNode(name="old-pkg", version="1.0.0", status=HealthStatus.OUTDATED)
        result = DependencyTreeResult(project_path="/tmp/test", roots=[root])

        render_tree(result, console=console, highlight_issues=True)
        output = buf.getvalue()
        assert "old-pkg" in output

    def test_tree_no_highlight(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        root = TreeNode(
            name="pkg", version="1.0.0", status=HealthStatus.VULNERABLE
        )
        result = DependencyTreeResult(project_path="/tmp/test", roots=[root])

        render_tree(result, console=console, highlight_issues=False)
        output = buf.getvalue()
        assert "pkg" in output

    def test_tree_display_depth_limit(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        grandchild = TreeNode(
            name="deep", version="1.0", status=HealthStatus.HEALTHY, depth=2
        )
        child = TreeNode(
            name="mid",
            version="1.0",
            status=HealthStatus.HEALTHY,
            depth=1,
            children=[grandchild],
        )
        root = TreeNode(
            name="top",
            version="1.0",
            status=HealthStatus.HEALTHY,
            depth=0,
            children=[child],
        )
        result = DependencyTreeResult(project_path="/tmp/test", roots=[root])

        render_tree(result, console=console, max_depth=0)
        output = buf.getvalue()
        # With max_depth=0, should show top-level but not deeper
        assert "top" in output

    def test_circular_dep_render(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        root = TreeNode(
            name="pkg-a",
            version="1.0",
            status=HealthStatus.UNKNOWN,
            parent_chain=frozenset({"pkg-a", "pkg-b"}),
        )
        result = DependencyTreeResult(
            project_path="/tmp/test",
            roots=[root],
            circular_deps=[["pkg-a", "pkg-b"]],
        )

        render_tree(result, console=console)
        output = buf.getvalue()
        assert "circular" in output.lower() or "pkg-a" in output


class TestRenderTreeJson:
    """Tests for JSON tree rendering."""

    def test_basic_json(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        root = TreeNode(name="requests", version="2.31.0", status=HealthStatus.HEALTHY)
        result = DependencyTreeResult(
            project_path="/tmp/test",
            roots=[root],
            files_scanned=["/tmp/test/requirements.txt"],
        )

        render_tree_json(result, console=console)
        output = buf.getvalue()
        # Should be valid JSON
        data = json.loads(output)
        assert data["tree"][0]["name"] == "requests"

    def test_json_with_children(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        child = TreeNode(name="click", version="8.1.0", status=HealthStatus.HEALTHY)
        root = TreeNode(
            name="flask",
            version="3.0.0",
            status=HealthStatus.HEALTHY,
            children=[child],
        )
        result = DependencyTreeResult(project_path="/tmp/test", roots=[root])

        render_tree_json(result, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert len(data["tree"][0]["children"]) == 1
        assert data["tree"][0]["children"][0]["name"] == "click"

    def test_json_with_circular_deps(self) -> None:
        buf = StringIO()
        console = Console(file=buf, force_terminal=True)

        result = DependencyTreeResult(
            project_path="/tmp/test",
            circular_deps=[["pkg-a", "pkg-b", "pkg-a"]],
        )
        render_tree_json(result, console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert len(data["circular_dependencies"]) == 1


class TestTreeNodeDepth:
    """Tests for tree depth and structure."""

    def test_depth_field(self) -> None:
        node = TreeNode(name="pkg", depth=5)
        assert node.depth == 5

    def test_parent_chain(self) -> None:
        chain = frozenset({"flask", "werkzeug"})
        node = TreeNode(name="click", parent_chain=chain)
        assert "flask" in node.parent_chain
        assert "werkzeug" in node.parent_chain

    def test_deeply_nested_tree(self) -> None:
        """Test a deeply nested tree structure."""
        leaf = TreeNode(
            name="d", version="1.0", status=HealthStatus.HEALTHY, depth=3
        )
        c = TreeNode(
            name="c",
            version="1.0",
            status=HealthStatus.HEALTHY,
            depth=2,
            children=[leaf],
        )
        b = TreeNode(
            name="b",
            version="1.0",
            status=HealthStatus.HEALTHY,
            depth=1,
            children=[c],
        )
        a = TreeNode(
            name="a",
            version="1.0",
            status=HealthStatus.HEALTHY,
            depth=0,
            children=[b],
        )

        result = DependencyTreeResult(project_path="/tmp/test", roots=[a])
        assert result.max_depth == 4  # 4 levels: a -> b -> c -> d
        flat = _flatten_tree(result.roots)
        assert len(flat) == 4
