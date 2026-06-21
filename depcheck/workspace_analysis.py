"""Cross-project dependency analysis for workspace."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from depcheck.models import PackageReport
    from depcheck.workspace import WorkspaceScanResult


@dataclass
class SharedDependency:
    """A dependency shared by multiple workspace members."""

    name: str
    versions: dict[str, str]  # member_name -> version
    members: list[str]  # member names that depend on this package

    @property
    def has_version_conflict(self) -> bool:
        """Check if there are version conflicts across members."""
        return len(set(self.versions.values())) > 1

    @property
    def unique_versions(self) -> set[str]:
        """Get the set of unique versions."""
        return set(self.versions.values())


@dataclass
class ConsolidationOpportunity:
    """A dependency that could be consolidated to workspace root."""

    name: str
    versions: dict[str, str]
    member_count: int
    recommended_version: str | None = None
    reason: str = ""


@dataclass
class WorkspaceAnalysis:
    """Results of cross-project dependency analysis."""

    shared_dependencies: dict[str, SharedDependency] = field(default_factory=dict)
    version_conflicts: list[SharedDependency] = field(default_factory=list)
    consolidation_opportunities: list[ConsolidationOpportunity] = field(default_factory=list)
    transitive_overlap: dict[str, list[str]] = field(default_factory=dict)  # dep -> members
    total_unique_packages: int = 0
    total_packages: int = 0


def analyze_workspace_dependencies(workspace_result: WorkspaceScanResult) -> WorkspaceAnalysis:
    """Analyze dependencies across all workspace members.

    Identifies:
    - Shared dependencies (used by multiple members)
    - Version conflicts (same package, different versions)
    - Consolidation opportunities (shared deps that could be hoisted)
    - Transitive dependency overlap

    Args:
        workspace_result: The aggregated workspace scan result.

    Returns:
        WorkspaceAnalysis with cross-project insights.
    """
    # Collect all packages from all members
    member_packages: dict[str, dict[str, PackageReport]] = {}
    all_package_names: set[str] = set()

    for member in workspace_result.members:
        if member.scan_result and hasattr(member.scan_result, "packages"):
            packages = {}
            for pkg in member.scan_result.packages:
                packages[pkg.name] = pkg
                all_package_names.add(pkg.name)
            member_packages[member.name] = packages

    # Find shared dependencies
    package_to_members: dict[str, list[str]] = defaultdict(list)
    package_versions: dict[str, dict[str, str]] = defaultdict(dict)

    for member_name, packages in member_packages.items():
        for pkg_name, pkg_report in packages.items():
            package_to_members[pkg_name].append(member_name)
            package_versions[pkg_name][member_name] = pkg_report.installed_version

    # Build shared dependencies
    shared_dependencies: dict[str, SharedDependency] = {}
    version_conflicts: list[SharedDependency] = []

    for pkg_name, members in package_to_members.items():
        if len(members) > 1:
            shared_dep = SharedDependency(
                name=pkg_name,
                versions=package_versions[pkg_name],
                members=members,
            )
            shared_dependencies[pkg_name] = shared_dep
            if shared_dep.has_version_conflict:
                version_conflicts.append(shared_dep)

    # Find consolidation opportunities (shared deps used by 2+ members)
    consolidation_opportunities: list[ConsolidationOpportunity] = []
    for pkg_name, shared_dep in shared_dependencies.items():
        if len(shared_dep.members) >= 2:
            # Recommend the highest version or most common version
            versions = list(shared_dep.versions.values())
            # Simple heuristic: recommend the highest version
            from packaging.version import Version

            def _version_key(v: str) -> Version:
                return Version(v) if v != "unknown" else Version("0")

            try:
                recommended = max(versions, key=_version_key)
            except Exception:
                recommended = versions[0]

            consolidation_opportunities.append(
                ConsolidationOpportunity(
                    name=pkg_name,
                    versions=shared_dep.versions,
                    member_count=len(shared_dep.members),
                    recommended_version=recommended,
                    reason=(
                        f"Used by {len(shared_dep.members)} members: "
                        f"{', '.join(shared_dep.members)}"
                    ),
                )
            )

    # Calculate transitive overlap (packages that appear as transitive deps in multiple members)
    # This is a simplified version - in reality we'd need to analyze the full dep tree
    transitive_overlap: dict[str, list[str]] = {}
    for pkg_name, members in package_to_members.items():
        if len(members) > 1:
            transitive_overlap[pkg_name] = members

    return WorkspaceAnalysis(
        shared_dependencies=shared_dependencies,
        version_conflicts=version_conflicts,
        consolidation_opportunities=consolidation_opportunities,
        transitive_overlap=transitive_overlap,
        total_unique_packages=len(all_package_names),
        total_packages=sum(len(pkgs) for pkgs in member_packages.values()),
    )
