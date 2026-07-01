"""Workspace/monorepo detection and analysis for depcheck."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from depcheck.models import ScanResult as ModelScanResult


class WorkspaceType(Enum):
    """Supported workspace types."""

    UV = "uv"
    POETRY = "poetry"
    HATCH = "hatch"
    PDM = "pdm"
    SETUPTOOLS = "setuptools"
    UNKNOWN = "unknown"


@dataclass
class WorkspaceConfig:
    """Configuration for a detected workspace."""

    workspace_type: WorkspaceType
    root_path: Path
    members: list[Path]
    config_path: Path


@dataclass
class WorkspaceMember:
    """A member project within a workspace."""

    name: str
    path: Path
    scan_result: ModelScanResult | None = None
    workspace_root: Path | None = None

    @property
    def relative_path(self) -> Path:
        """Path relative to workspace root."""
        if self.workspace_root:
            try:
                return self.path.relative_to(self.workspace_root)
            except ValueError:
                pass
        return Path(self.path.name)


@dataclass
class WorkspaceScanResult:
    """Aggregated scan results for an entire workspace."""

    root: Path
    members: list[WorkspaceMember]
    workspace_type: WorkspaceType
    errors: list[str] = field(default_factory=list)

    @property
    def total_packages(self) -> int:
        """Total number of packages across all members."""
        total = 0
        for member in self.members:
            if member.scan_result and hasattr(member.scan_result, "packages"):
                total += len(member.scan_result.packages)
        return total

    @property
    def total_vulnerabilities(self) -> int:
        """Total vulnerabilities across all members."""
        total = 0
        for member in self.members:
            if member.scan_result:
                # Check for SeverityBreakdown (from audit)
                if hasattr(member.scan_result, "severity_breakdown"):
                    sb = getattr(member.scan_result, "severity_breakdown", None)
                    if sb and hasattr(sb, "total"):
                        total += sb.total
                # Fallback: count vulnerable packages
                elif hasattr(member.scan_result, "vulnerable_count"):
                    total += member.scan_result.vulnerable_count
        return total


def detect_workspace_config(root: Path) -> WorkspaceConfig | None:
    """Detect workspace configuration in a project root.

    Supports uv, Poetry, Hatch, PDM, and setuptools/PEP 621 workspace configurations.

    Args:
        root: Project root directory to check.

    Returns:
        WorkspaceConfig if a workspace is detected, None otherwise.
    """
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return None

    try:
        with open(pyproject, "rb") as f:
            data = tomllib.load(f)
    except (tomllib.TOMLDecodeError, OSError):
        return None

    # Check uv workspace: [tool.uv.workspace] members = [...]
    if _is_uv_workspace(data):
        return _parse_uv_workspace(root, pyproject, data)

    # Check Poetry workspace: [tool.poetry.workspace] packages = [...]
    if _is_poetry_workspace(data):
        return _parse_poetry_workspace(root, pyproject, data)

    # Check Hatch workspace: [tool.hatch.workspace] packages = [...]
    if _is_hatch_workspace(data):
        return _parse_hatch_workspace(root, pyproject, data)

    # Check PDM workspace: [tool.pdm.workspace] packages = [...]
    if _is_pdm_workspace(data):
        return _parse_pdm_workspace(root, pyproject, data)

    # Check setuptools/PEP 621 workspace: [project.workspace] members = [...]
    if _is_setuptools_workspace(data):
        return _parse_setuptools_workspace(root, pyproject, data)

    return None


def _is_uv_workspace(data: dict) -> bool:
    """Check if data contains uv workspace configuration."""
    return "tool" in data and "uv" in data["tool"] and "workspace" in data["tool"]["uv"]


def _parse_uv_workspace(root: Path, config_path: Path, data: dict) -> WorkspaceConfig:
    """Parse uv workspace configuration."""
    ws = data["tool"]["uv"]["workspace"]
    members = ws.get("members", [])
    member_paths = _expand_globs(root, members)
    return WorkspaceConfig(
        workspace_type=WorkspaceType.UV,
        root_path=root,
        members=member_paths,
        config_path=config_path,
    )


def _is_poetry_workspace(data: dict) -> bool:
    """Check if data contains Poetry workspace configuration."""
    return "tool" in data and "poetry" in data["tool"] and "workspace" in data["tool"]["poetry"]


def _parse_poetry_workspace(root: Path, config_path: Path, data: dict) -> WorkspaceConfig:
    """Parse Poetry workspace configuration."""
    ws = data["tool"]["poetry"]["workspace"]
    packages = ws.get("packages", [])
    member_paths = _expand_globs(root, packages)
    return WorkspaceConfig(
        workspace_type=WorkspaceType.POETRY,
        root_path=root,
        members=member_paths,
        config_path=config_path,
    )


def _is_hatch_workspace(data: dict) -> bool:
    """Check if data contains Hatch workspace configuration."""
    return "tool" in data and "hatch" in data["tool"] and "workspace" in data["tool"]["hatch"]


def _parse_hatch_workspace(root: Path, config_path: Path, data: dict) -> WorkspaceConfig:
    """Parse Hatch workspace configuration."""
    ws = data["tool"]["hatch"]["workspace"]
    packages = ws.get("packages", [])
    member_paths = _expand_globs(root, packages)
    return WorkspaceConfig(
        workspace_type=WorkspaceType.HATCH,
        root_path=root,
        members=member_paths,
        config_path=config_path,
    )


def _is_pdm_workspace(data: dict) -> bool:
    """Check if data contains PDM workspace configuration."""
    return "tool" in data and "pdm" in data["tool"] and "workspace" in data["tool"]["pdm"]


def _parse_pdm_workspace(root: Path, config_path: Path, data: dict) -> WorkspaceConfig:
    """Parse PDM workspace configuration."""
    ws = data["tool"]["pdm"]["workspace"]
    packages = ws.get("packages", [])
    member_paths = _expand_globs(root, packages)
    return WorkspaceConfig(
        workspace_type=WorkspaceType.PDM,
        root_path=root,
        members=member_paths,
        config_path=config_path,
    )


def _is_setuptools_workspace(data: dict) -> bool:
    """Check if data contains setuptools/PEP 621 workspace configuration."""
    return "project" in data and "workspace" in data["project"]


def _parse_setuptools_workspace(root: Path, config_path: Path, data: dict) -> WorkspaceConfig:
    """Parse setuptools/PEP 621 workspace configuration."""
    ws = data["project"]["workspace"]
    members = ws.get("members", [])
    member_paths = _expand_globs(root, members)
    return WorkspaceConfig(
        workspace_type=WorkspaceType.SETUPTOOLS,
        root_path=root,
        members=member_paths,
        config_path=config_path,
    )


def _expand_globs(root: Path, patterns: list[str]) -> list[Path]:
    """Expand glob patterns to find member project directories.

    Args:
        root: Workspace root directory.
        patterns: List of glob patterns (e.g., ["packages/*", "libs/*"]).

    Returns:
        Sorted list of member project paths that contain pyproject.toml.
    """
    results = []
    for pattern in patterns:
        for match in root.glob(pattern):
            if match.is_dir() and (match / "pyproject.toml").exists():
                results.append(match)
    # Sort for deterministic output
    return sorted(results, key=lambda p: str(p.relative_to(root)))


def scan_workspace(
    root: Path | str,
    check_vulnerabilities: bool = True,
    check_licenses: bool = False,
    allowed_license_categories: list | None = None,
    denied_licenses: list[str] | None = None,
) -> WorkspaceScanResult:
    """Scan all member projects in a workspace and aggregate results.

    Args:
        root: Workspace root directory.
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.
        allowed_license_categories: List of allowed license categories.
        denied_licenses: List of specific SPDX IDs to deny.

    Returns:
        WorkspaceScanResult with aggregated scan results for all members.
    """
    from depcheck.scanner import scan_project

    root = Path(root).resolve()

    # Detect workspace config
    config = detect_workspace_config(root)
    if config is None:
        return WorkspaceScanResult(
            root=root,
            members=[],
            workspace_type=WorkspaceType.UNKNOWN,
            errors=["No workspace configuration detected"],
        )

    # Scan each member project
    members: list[WorkspaceMember] = []
    for member_path in config.members:
        try:
            scan_result = scan_project(
                project_path=member_path,
                check_vulnerabilities=check_vulnerabilities,
                check_licenses=check_licenses,
                allowed_license_categories=allowed_license_categories,
                denied_licenses=denied_licenses,
            )
            member = WorkspaceMember(
                name=member_path.name,
                path=member_path,
                scan_result=scan_result,
                workspace_root=root,
            )
            members.append(member)
        except Exception as exc:
            # Create error member
            from depcheck.models import ScanResult as ModelScanResult

            error_result = ModelScanResult(
                project_path=str(member_path),
                errors=[f"Failed to scan: {exc}"],
            )
            member = WorkspaceMember(
                name=member_path.name,
                path=member_path,
                scan_result=error_result,
                workspace_root=root,
            )
            members.append(member)

    return WorkspaceScanResult(
        root=root,
        members=members,
        workspace_type=config.workspace_type,
    )
