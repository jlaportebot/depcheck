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
    from depcheck.workspace import WorkspaceMember, WorkspaceScanResult, WorkspaceType

    result = WorkspaceScanResult(
        root=Path("/tmp/workspace"),
        members=[],
        workspace_type=WorkspaceType.UV,
    )
    assert result.workspace_type == WorkspaceType.UV
    assert result.total_packages == 0
    assert result.total_vulnerabilities == 0


def test_scan_workspace():
    """Test scanning a workspace with multiple members."""
    import tempfile
    from pathlib import Path

    from depcheck.workspace import WorkspaceScanResult, scan_workspace

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
            dependencies = ["requests>=2.28"]
        """)
        (root / "packages" / "pkg2").mkdir()
        (root / "packages" / "pkg2" / "pyproject.toml").write_text("""
            [project]
            name = "pkg2"
            dependencies = ["httpx>=0.24"]
        """)

        result = scan_workspace(root, check_vulnerabilities=False)
        assert isinstance(result, WorkspaceScanResult)
        assert len(result.members) == 2
        assert result.total_packages >= 2


def test_workspace_analysis_shared_dependencies():
    """Test cross-project analysis detects shared dependencies."""
    from pathlib import Path

    from depcheck.models import HealthStatus, PackageReport
    from depcheck.workspace import WorkspaceMember, WorkspaceScanResult, WorkspaceType
    from depcheck.workspace_analysis import analyze_workspace_dependencies

    # Create mock scan results with overlapping dependencies
    pkg1_report = PackageReport(
        name="requests",
        installed_version="2.28.0",
        latest_version="2.31.0",
        status=HealthStatus.OUTDATED,
    )
    pkg2_report = PackageReport(
        name="urllib3",
        installed_version="1.26.15",
        latest_version="2.0.0",
        status=HealthStatus.OUTDATED,
    )
    pkg3_report = PackageReport(
        name="requests",
        installed_version="2.28.0",
        latest_version="2.31.0",
        status=HealthStatus.OUTDATED,
    )
    pkg4_report = PackageReport(
        name="certifi",
        installed_version="2023.01.01",
        latest_version="2023.07.22",
        status=HealthStatus.OUTDATED,
    )

    class MockScanResult:
        def __init__(self, packages):
            self.packages = packages

    members = [
        WorkspaceMember(
            name="pkg1",
            path=Path("packages/pkg1"),
            scan_result=MockScanResult([pkg1_report, pkg2_report]),
            workspace_root=Path("/tmp"),
        ),
        WorkspaceMember(
            name="pkg2",
            path=Path("packages/pkg2"),
            scan_result=MockScanResult([pkg3_report, pkg4_report]),
            workspace_root=Path("/tmp"),
        ),
    ]
    workspace_result = WorkspaceScanResult(
        root=Path("/tmp"), members=members, workspace_type=WorkspaceType.UV
    )

    analysis = analyze_workspace_dependencies(workspace_result)

    # Should detect shared dependency
    assert "requests" in analysis.shared_dependencies
    shared_requests = analysis.shared_dependencies["requests"]
    assert len(shared_requests.members) == 2
    assert "pkg1" in shared_requests.members
    assert "pkg2" in shared_requests.members

    # Should NOT have version conflict (both same version)
    assert not shared_requests.has_version_conflict
    assert "requests" not in [vc.name for vc in analysis.version_conflicts]

    # Should have consolidation opportunity
    assert len(analysis.consolidation_opportunities) >= 1
    requests_opp = next(
        (o for o in analysis.consolidation_opportunities if o.name == "requests"),
        None,
    )
    assert requests_opp is not None
    assert requests_opp.member_count == 2


def test_workspace_analysis_version_conflict():
    """Test cross-project analysis detects version conflicts."""
    from pathlib import Path

    from depcheck.models import HealthStatus, PackageReport
    from depcheck.workspace import WorkspaceMember, WorkspaceScanResult, WorkspaceType
    from depcheck.workspace_analysis import analyze_workspace_dependencies

    # Create mock scan results with version conflict
    pkg1_report = PackageReport(
        name="requests",
        installed_version="2.28.0",
        latest_version="2.31.0",
        status=HealthStatus.OUTDATED,
    )
    pkg2_report = PackageReport(
        name="requests",
        installed_version="2.25.0",
        latest_version="2.31.0",
        status=HealthStatus.OUTDATED,
    )

    class MockScanResult:
        def __init__(self, packages):
            self.packages = packages

    members = [
        WorkspaceMember(
            name="pkg1",
            path=Path("packages/pkg1"),
            scan_result=MockScanResult([pkg1_report]),
            workspace_root=Path("/tmp"),
        ),
        WorkspaceMember(
            name="pkg2",
            path=Path("packages/pkg2"),
            scan_result=MockScanResult([pkg2_report]),
            workspace_root=Path("/tmp"),
        ),
    ]
    workspace_result = WorkspaceScanResult(
        root=Path("/tmp"), members=members, workspace_type=WorkspaceType.UV
    )

    analysis = analyze_workspace_dependencies(workspace_result)

    # Should detect shared dependency
    assert "requests" in analysis.shared_dependencies
    shared_requests = analysis.shared_dependencies["requests"]
    assert len(shared_requests.members) == 2

    # SHOULD have version conflict
    assert shared_requests.has_version_conflict
    assert "requests" in [vc.name for vc in analysis.version_conflicts]
    assert len(analysis.version_conflicts) == 1


def test_render_workspace_table():
    """Test rendering workspace table output."""
    from io import StringIO
    from pathlib import Path

    from rich.console import Console

    from depcheck.models import HealthStatus, PackageReport
    from depcheck.workspace import WorkspaceMember, WorkspaceScanResult, WorkspaceType
    from depcheck.workspace_report import render_workspace_table

    # Create mock scan results
    pkg1_report = PackageReport(
        name="requests",
        installed_version="2.28.0",
        latest_version="2.31.0",
        status=HealthStatus.OUTDATED,
    )

    class MockScanResult:
        def __init__(self, packages):
            self.packages = packages
            self.vulnerable_count = 1

    members = [
        WorkspaceMember(
            name="pkg1",
            path=Path("packages/pkg1"),
            scan_result=MockScanResult([pkg1_report]),
            workspace_root=Path("/tmp/workspace"),
        ),
    ]
    workspace_result = WorkspaceScanResult(
        root=Path("/tmp/workspace"),
        members=members,
        workspace_type=WorkspaceType.UV,
    )

    # Capture output
    output_buffer = StringIO()
    console = Console(file=output_buffer, force_terminal=False, no_color=True, width=120)
    render_workspace_table(workspace_result, console=console)

    output = output_buffer.getvalue()
    assert "pkg1" in output
    assert "Workspace Health Grade" in output
    assert "Member Projects" in output


def test_render_workspace_json():
    """Test rendering workspace JSON output."""
    import json
    from pathlib import Path

    from depcheck.models import HealthStatus, PackageReport
    from depcheck.workspace import WorkspaceMember, WorkspaceScanResult, WorkspaceType
    from depcheck.workspace_report import render_workspace_json

    # Create mock scan results
    pkg1_report = PackageReport(
        name="requests",
        installed_version="2.28.0",
        latest_version="2.31.0",
        status=HealthStatus.OUTDATED,
    )

    class MockScanResult:
        def __init__(self, packages):
            self.packages = packages
            self.vulnerable_count = 1

    members = [
        WorkspaceMember(
            name="pkg1",
            path=Path("packages/pkg1"),
            scan_result=MockScanResult([pkg1_report]),
            workspace_root=Path("/tmp/workspace"),
        ),
    ]
    workspace_result = WorkspaceScanResult(
        root=Path("/tmp/workspace"),
        members=members,
        workspace_type=WorkspaceType.UV,
    )

    json_output = render_workspace_json(workspace_result)
    data = json.loads(json_output)

    assert data["workspace"]["type"] == "uv"
    assert data["workspace"]["member_count"] == 1
    assert data["workspace"]["total_packages"] == 1
    assert "members" in data
    assert len(data["members"]) == 1
    assert data["members"][0]["name"] == "pkg1"


def test_calculate_workspace_grade():
    """Test workspace health grade calculation."""
    from pathlib import Path

    from depcheck.models import HealthStatus, PackageReport
    from depcheck.workspace import WorkspaceMember, WorkspaceScanResult, WorkspaceType
    from depcheck.workspace_report import calculate_workspace_grade

    # Healthy workspace (no vulns)
    class MockScanResultHealthy:
        def __init__(self, packages):
            self.packages = packages
            self.vulnerable_count = 0

    healthy_pkg = PackageReport(
        name="requests",
        installed_version="2.31.0",
        latest_version="2.31.0",
        status=HealthStatus.HEALTHY,
    )

    members = [
        WorkspaceMember(
            name="pkg1",
            path=Path("packages/pkg1"),
            scan_result=MockScanResultHealthy([healthy_pkg]),
            workspace_root=Path("/tmp"),
        ),
    ]
    workspace_result = WorkspaceScanResult(
        root=Path("/tmp"), members=members, workspace_type=WorkspaceType.UV
    )

    grade = calculate_workspace_grade(workspace_result)
    assert grade.grade == "A"
    assert grade.score == 0.0

    # Vulnerable workspace
    class MockScanResultVuln:
        def __init__(self, packages):
            self.packages = packages
            self.vulnerable_count = 5

    vuln_pkg = PackageReport(
        name="requests",
        installed_version="2.28.0",
        latest_version="2.31.0",
        status=HealthStatus.VULNERABLE,
    )

    members = [
        WorkspaceMember(
            name="pkg1",
            path=Path("packages/pkg1"),
            scan_result=MockScanResultVuln([vuln_pkg]),
            workspace_root=Path("/tmp"),
        ),
    ]
    workspace_result = WorkspaceScanResult(
        root=Path("/tmp"), members=members, workspace_type=WorkspaceType.UV
    )

    grade = calculate_workspace_grade(workspace_result)
    assert grade.grade in ("D", "F")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
