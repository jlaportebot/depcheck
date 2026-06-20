"""Tests for workspace/monorepo support."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest


def test_workspace_config_detection_uv():
    """Test detection of uv workspace configuration."""
    from depcheck.workspace import WorkspaceType, detect_workspace_config

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [project]
            name = "my-workspace"
            [tool.uv.workspace]
            members = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [project]
            name = "pkg1"
            dependencies = ["requests"]
        """)
        (root / "packages" / "pkg2").mkdir()
        (root / "packages" / "pkg2" / "pyproject.toml").write_text("""
            [project]
            name = "pkg2"
            dependencies = ["httpx"]
        """)

        config = detect_workspace_config(root)
        assert config is not None
        assert config.workspace_type == WorkspaceType.UV
        assert len(config.members) == 2


def test_workspace_config_detection_poetry():
    """Test detection of Poetry workspace configuration."""
    from depcheck.workspace import WorkspaceType, detect_workspace_config

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [tool.poetry.workspace]
            mode = "explicit"
            packages = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [tool.poetry]
            name = "pkg1"
            dependencies = { requests = "^2.28" }
        """)

        config = detect_workspace_config(root)
        assert config is not None
        assert config.workspace_type == WorkspaceType.POETRY
        assert len(config.members) == 1


def test_workspace_config_detection_hatch():
    """Test detection of Hatch workspace configuration."""
    from depcheck.workspace import WorkspaceType, detect_workspace_config

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [tool.hatch.workspace]
            packages = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [project]
            name = "pkg1"
            dependencies = ["requests"]
        """)

        config = detect_workspace_config(root)
        assert config is not None
        assert config.workspace_type == WorkspaceType.HATCH


def test_workspace_config_detection_pdm():
    """Test detection of PDM workspace configuration."""
    from depcheck.workspace import WorkspaceType, detect_workspace_config

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [tool.pdm.workspace]
            packages = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [project]
            name = "pkg1"
            dependencies = ["requests"]
        """)

        config = detect_workspace_config(root)
        assert config is not None
        assert config.workspace_type == WorkspaceType.PDM


def test_workspace_config_detection_setuptools():
    """Test detection of setuptools/PEP 621 workspace configuration."""
    from depcheck.workspace import WorkspaceType, detect_workspace_config

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [project]
            name = "my-workspace"
            [project.workspace]
            members = ["packages/*"]
        """)
        (root / "packages").mkdir()
        (root / "packages" / "pkg1").mkdir()
        (root / "packages" / "pkg1" / "pyproject.toml").write_text("""
            [project]
            name = "pkg1"
            dependencies = ["requests"]
        """)

        config = detect_workspace_config(root)
        assert config is not None
        assert config.workspace_type == WorkspaceType.SETUPTOOLS


def test_workspace_config_no_workspace_returns_none():
    """Test that non-workspace projects return None."""
    from depcheck.workspace import detect_workspace_config

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("""
            [project]
            name = "regular-project"
            dependencies = ["requests"]
        """)

        config = detect_workspace_config(root)
        assert config is None


def test_workspace_config_no_pyproject_returns_none():
    """Test that directories without pyproject.toml return None."""
    from depcheck.workspace import detect_workspace_config

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        # No pyproject.toml

        config = detect_workspace_config(root)
        assert config is None


def test_workspace_member_model():
    """Test WorkspaceMember data model."""
    from pathlib import Path

    from depcheck.workspace import WorkspaceMember

    member = WorkspaceMember(
        name="pkg1",
        path=Path("/tmp/workspace/packages/pkg1"),
        workspace_root=Path("/tmp/workspace"),
    )
    assert member.name == "pkg1"
    assert member.relative_path == Path("packages/pkg1")


def test_workspace_scan_result_model():
    """Test WorkspaceScanResult data model."""
    from pathlib import Path

    from depcheck.workspace import WorkspaceMember, WorkspaceScanResult, WorkspaceType

    result = WorkspaceScanResult(
        root=Path("/tmp/workspace"),
        members=[],
        workspace_type=WorkspaceType.UV,
    )
    assert result.workspace_type == WorkspaceType.UV
    assert result.total_packages == 0
    assert result.total_vulnerabilities == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
