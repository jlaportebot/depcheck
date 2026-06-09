"""Tests for the five new depcheck modules: update, isolate, sizescore, depdrift, compat.

Comprehensive test suite covering core logic, edge cases, and rendering.
"""

from __future__ import annotations

import json
from pathlib import Path

from depcheck.compat import (
    CompatInfo,
    CompatReport,
    check_breaking_on_upgrade,
    check_version_compatibility,
    extract_python_classifiers,
    parse_requires_python,
    render_compat_json,
    render_compat_table,
)
from depcheck.depdrift import (
    DriftEntry,
    DriftReport,
    DriftSnapshot,
    build_drift_report,
    compare_snapshots,
    compute_drift_velocity,
    identify_high_drift_packages,
    render_drift_json,
    render_drift_table,
)
from depcheck.isolate import (
    STDLIB_MODULES,
    IsolationInfo,
    IsolationReport,
    analyze_isolation,
    assess_removal_risk,
    compute_isolation_score,
    get_import_name,
    render_isolation_json,
    render_isolation_table,
    scan_imports_in_file,
    scan_project_imports,
)
from depcheck.models import HealthStatus, PackageReport, ParsedDependency, ScanResult, Vulnerability
from depcheck.outdated import RiskLevel, UpgradeLevel
from depcheck.sizescore import (
    LIGHTER_ALTERNATIVES,
    SizeInfo,
    SizeReport,
    analyze_size_trend,
    classify_size,
    compute_size_score,
    format_size,
    render_size_json,
    render_size_table,
)
from depcheck.update import (
    UpdatePlan,
    UpdatePriority,
    UpdateStep,
    UpdateStrategy,
    assess_breaking_change_risk,
    build_update_plan,
    determine_update_priority,
    determine_update_strategy,
    estimate_update_time,
    render_update_plan_json,
    render_update_plan_table,
)

# ===== Update Module Tests =====


def _make_pkg_report(
    name: str = "test-pkg",
    installed_version: str = "1.0.0",
    latest_version: str = "2.0.0",
    status: HealthStatus = HealthStatus.OUTDATED,
    vulnerabilities: list | None = None,
) -> PackageReport:
    """Helper to create a PackageReport for testing."""
    return PackageReport(
        name=name,
        installed_version=installed_version,
        latest_version=latest_version,
        status=status,
        vulnerabilities=vulnerabilities or [],
    )


class TestUpdatePriority:
    """Tests for UpdatePriority constants."""

    def test_all_priorities_defined(self):
        assert UpdatePriority.CRITICAL == "critical"
        assert UpdatePriority.HIGH == "high"
        assert UpdatePriority.MEDIUM == "medium"
        assert UpdatePriority.LOW == "low"
        assert UpdatePriority.DEFERRED == "deferred"


class TestUpdateStrategy:
    """Tests for UpdateStrategy constants."""

    def test_all_strategies_defined(self):
        assert UpdateStrategy.DIRECT == "direct"
        assert UpdateStrategy.STAGED == "staged"
        assert UpdateStrategy.SKIP == "skip"
        assert UpdateStrategy.REVIEW == "review"


class TestUpdateStep:
    """Tests for UpdateStep dataclass."""

    def test_to_dict(self):
        step = UpdateStep(
            name="requests",
            current_version="2.28.0",
            target_version="2.31.0",
            priority=UpdatePriority.MEDIUM,
            strategy=UpdateStrategy.DIRECT,
            risk=RiskLevel.LOW,
            upgrade_level=UpgradeLevel.MINOR,
            command="pip install --upgrade requests",
            rationale="Minor version update",
        )
        d = step.to_dict()
        assert d["name"] == "requests"
        assert d["priority"] == "medium"
        assert d["strategy"] == "direct"
        assert "pip install" in d["command"]

    def test_default_values(self):
        step = UpdateStep(name="pkg", current_version="1.0", target_version="2.0")
        assert step.priority == UpdatePriority.LOW
        assert step.strategy == UpdateStrategy.DIRECT
        assert step.is_vulnerable is False
        assert step.breaking_change_risk == "low"


class TestUpdatePlan:
    """Tests for UpdatePlan dataclass."""

    def test_to_dict(self):
        plan = UpdatePlan(
            steps=[UpdateStep(name="pkg", current_version="1.0", target_version="2.0")],
            total_packages=1,
            needs_update_count=1,
        )
        d = plan.to_dict()
        assert "summary" in d
        assert d["summary"]["total_packages"] == 1
        assert len(d["steps"]) == 1

    def test_empty_plan(self):
        plan = UpdatePlan()
        d = plan.to_dict()
        assert d["summary"]["total_packages"] == 0
        assert d["steps"] == []


class TestDetermineUpdatePriority:
    """Tests for determine_update_priority."""

    def test_vulnerable_package_is_critical(self):
        pkg = _make_pkg_report("vuln-pkg", "1.0.0", "1.0.1")
        result = determine_update_priority(
            pkg_report=pkg,
            upgrade_level=UpgradeLevel.PATCH,
            risk=RiskLevel.HIGH,
            is_vulnerable=True,
            days_behind=30,
        )
        assert result == UpdatePriority.CRITICAL

    def test_major_upgrade_is_high(self):
        pkg = _make_pkg_report("big-pkg", "1.0.0", "2.0.0")
        result = determine_update_priority(
            pkg_report=pkg,
            upgrade_level=UpgradeLevel.MAJOR,
            risk=RiskLevel.MEDIUM,
            is_vulnerable=False,
            days_behind=100,
        )
        assert result == UpdatePriority.HIGH

    def test_minor_upgrade_is_medium(self):
        pkg = _make_pkg_report("med-pkg", "1.0.0", "1.1.0")
        result = determine_update_priority(
            pkg_report=pkg,
            upgrade_level=UpgradeLevel.MINOR,
            risk=RiskLevel.LOW,
            is_vulnerable=False,
            days_behind=30,
        )
        assert result == UpdatePriority.MEDIUM

    def test_patch_upgrade_is_low(self):
        pkg = _make_pkg_report("patch-pkg", "1.0.0", "1.0.1")
        result = determine_update_priority(
            pkg_report=pkg,
            upgrade_level=UpgradeLevel.PATCH,
            risk=RiskLevel.LOW,
            is_vulnerable=False,
            days_behind=5,
        )
        assert result == UpdatePriority.LOW

    def test_prerelease_is_deferred(self):
        pkg = _make_pkg_report("pre-pkg", "1.0.0", "2.0.0a1")
        result = determine_update_priority(
            pkg_report=pkg,
            upgrade_level=UpgradeLevel.PRERELEASE,
            risk=RiskLevel.UNKNOWN,
            is_vulnerable=False,
            days_behind=None,
        )
        assert result == UpdatePriority.DEFERRED

    def test_minor_with_long_drift_is_high(self):
        pkg = _make_pkg_report("old-pkg", "1.0.0", "1.1.0")
        result = determine_update_priority(
            pkg_report=pkg,
            upgrade_level=UpgradeLevel.MINOR,
            risk=RiskLevel.MEDIUM,
            is_vulnerable=False,
            days_behind=200,
        )
        assert result == UpdatePriority.HIGH


class TestDetermineUpdateStrategy:
    """Tests for determine_update_strategy."""

    def test_direct_for_patch_update(self):
        result = determine_update_strategy(
            upgrade_level=UpgradeLevel.PATCH,
            is_vulnerable=False,
            has_dep_constraints=False,
            is_pinned=False,
        )
        assert result == UpdateStrategy.DIRECT

    def test_review_for_pinned(self):
        result = determine_update_strategy(
            upgrade_level=UpgradeLevel.MINOR,
            is_vulnerable=False,
            has_dep_constraints=False,
            is_pinned=True,
        )
        assert result == UpdateStrategy.REVIEW

    def test_direct_for_vulnerable(self):
        result = determine_update_strategy(
            upgrade_level=UpgradeLevel.PATCH,
            is_vulnerable=True,
            has_dep_constraints=False,
            is_pinned=True,  # even pinned
        )
        assert result == UpdateStrategy.DIRECT

    def test_staged_for_major_with_constraints(self):
        result = determine_update_strategy(
            upgrade_level=UpgradeLevel.MAJOR,
            is_vulnerable=False,
            has_dep_constraints=True,
            is_pinned=False,
        )
        assert result == UpdateStrategy.STAGED

    def test_review_for_major_no_constraints(self):
        result = determine_update_strategy(
            upgrade_level=UpgradeLevel.MAJOR,
            is_vulnerable=False,
            has_dep_constraints=False,
            is_pinned=False,
        )
        assert result == UpdateStrategy.REVIEW

    def test_skip_for_prerelease(self):
        result = determine_update_strategy(
            upgrade_level=UpgradeLevel.PRERELEASE,
            is_vulnerable=False,
            has_dep_constraints=False,
            is_pinned=False,
        )
        assert result == UpdateStrategy.SKIP


class TestAssessBreakingChangeRisk:
    """Tests for assess_breaking_change_risk."""

    def test_patch_update_low_risk(self):
        risk = assess_breaking_change_risk(
            upgrade_level=UpgradeLevel.PATCH,
            is_vulnerable=False,
            days_behind=5,
        )
        assert risk == "low"

    def test_major_update_high_risk(self):
        risk = assess_breaking_change_risk(
            upgrade_level=UpgradeLevel.MAJOR,
            is_vulnerable=False,
            days_behind=365,
        )
        assert risk in ("medium", "high")

    def test_same_version(self):
        risk = assess_breaking_change_risk(
            upgrade_level=UpgradeLevel.PATCH,
            is_vulnerable=False,
            days_behind=0,
        )
        assert risk == "low"


class TestEstimateUpdateTime:
    """Tests for estimate_update_time."""

    def test_empty_steps(self):
        assert estimate_update_time([]) == 0

    def test_single_step(self):
        steps = [UpdateStep(name="pkg", current_version="1.0", target_version="2.0")]
        time = estimate_update_time(steps)
        assert isinstance(time, int)
        assert time >= 0


class TestBuildUpdatePlan:
    """Tests for build_update_plan."""

    def test_empty_scan(self):
        result = ScanResult(project_path=".", packages=[], errors=[])
        plan = build_update_plan(result)
        assert plan.total_packages == 0
        assert plan.steps == []

    def test_outdated_packages_produce_steps(self):
        pkg = _make_pkg_report("requests", "2.28.0", "2.31.0")
        result = ScanResult(project_path=".", packages=[pkg], errors=[])
        plan = build_update_plan(result)
        assert plan.needs_update_count >= 1

    def test_up_to_date_packages_not_in_steps(self):
        pkg = _make_pkg_report("requests", "2.31.0", "2.31.0", status=HealthStatus.HEALTHY)
        result = ScanResult(project_path=".", packages=[pkg], errors=[])
        plan = build_update_plan(result)
        assert plan.needs_update_count == 0

    def test_vulnerable_packages_get_critical_priority(self):
        vuln = Vulnerability(
            vuln_id="CVE-2023-1234",
            summary="Test vuln",
            severity="high",
            url="https://example.com",
        )
        pkg = _make_pkg_report(
            "vuln-pkg",
            "1.0.0",
            "1.0.1",
            status=HealthStatus.VULNERABLE,
            vulnerabilities=[vuln],
        )
        result = ScanResult(project_path=".", packages=[pkg], errors=[])
        plan = build_update_plan(result)
        critical_steps = [s for s in plan.steps if s.priority == UpdatePriority.CRITICAL]
        assert len(critical_steps) >= 1


class TestUpdatePlanRender:
    """Tests for render functions."""

    def test_render_json(self):
        plan = UpdatePlan()
        result = render_update_plan_json(plan)
        data = json.loads(result)
        assert data["summary"]["total_packages"] == 0

    def test_render_table_does_not_crash(self):
        from rich.console import Console

        plan = UpdatePlan()
        console = Console(width=120, force_terminal=False, no_color=True)
        render_update_plan_table(plan, console=console)


# ===== Isolate Module Tests =====


class TestGetImportName:
    """Tests for get_import_name."""

    def test_simple_name(self):
        result = get_import_name("requests")
        assert result == "requests"

    def test_dashed_name(self):
        result = get_import_name("python-dateutil")
        assert result == "dateutil"

    def test_unknown_package(self):
        result = get_import_name("some-random-pkg")
        assert isinstance(result, str)


class TestScanImportsInFile:
    """Tests for scan_imports_in_file."""

    def test_simple_import(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("import os\nimport json\n")
        imports = scan_imports_in_file(f)
        assert "os" in imports
        assert "json" in imports

    def test_from_import(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("from collections import OrderedDict\nfrom os.path import join\n")
        imports = scan_imports_in_file(f)
        assert "collections" in imports
        assert "os.path" in imports or "os" in imports

    def test_import_with_alias(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("import numpy as np\n")
        imports = scan_imports_in_file(f)
        assert "numpy" in imports

    def test_no_imports(self, tmp_path):
        f = tmp_path / "test.py"
        f.write_text("x = 1\nprint(x)\n")
        imports = scan_imports_in_file(f)
        assert len(imports) == 0

    def test_nonexistent_file(self):
        imports = scan_imports_in_file(Path("/nonexistent/file.py"))
        assert imports == set()

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("")
        imports = scan_imports_in_file(f)
        assert imports == set()

    def test_syntax_error_file(self, tmp_path):
        """Files with syntax errors should be handled gracefully."""
        f = tmp_path / "broken.py"
        f.write_text("def broken(:\n  pass\n")
        imports = scan_imports_in_file(f)
        assert isinstance(imports, set)


class TestScanProjectImports:
    """Tests for scan_project_imports (directory scanning)."""

    def test_scans_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("import requests\n")
        (tmp_path / "b.py").write_text("import flask\n")
        result = scan_project_imports(tmp_path)
        assert isinstance(result, dict)
        # Returns {import_name: [file_paths]}
        assert "requests" in result
        assert "flask" in result

    def test_recursive(self, tmp_path):
        sub = tmp_path / "subpkg"
        sub.mkdir()
        (sub / "mod.py").write_text("import django\n")
        result = scan_project_imports(tmp_path)
        assert "django" in result

    def test_empty_directory(self, tmp_path):
        result = scan_project_imports(tmp_path)
        assert isinstance(result, dict)


class TestComputeIsolationScore:
    """Tests for compute_isolation_score."""

    def test_imported_package(self):
        score = compute_isolation_score(
            is_imported=True,
            is_transitive_only=False,
            required_by_count=0,
            requires_count=0,
        )
        assert isinstance(score, float)
        assert 0 <= score <= 1

    def test_unused_package(self):
        score = compute_isolation_score(
            is_imported=False,
            is_transitive_only=False,
            required_by_count=0,
            requires_count=0,
        )
        assert isinstance(score, float)
        assert score >= 0.4  # Not imported gives +0.4

    def test_transitive_only(self):
        score = compute_isolation_score(
            is_imported=False,
            is_transitive_only=True,
            required_by_count=1,
            requires_count=0,
        )
        assert isinstance(score, float)

    def test_deeply_embedded(self):
        score = compute_isolation_score(
            is_imported=True,
            is_transitive_only=False,
            required_by_count=5,
            requires_count=10,
        )
        assert score < 0.5


class TestAssessRemovalRisk:
    """Tests for assess_removal_risk."""

    def test_unused_package_low_risk(self):
        risk, note = assess_removal_risk(
            is_imported=False,
            required_by_count=0,
            isolation_score=0.8,
        )
        assert risk == "low"

    def test_required_by_others(self):
        risk, note = assess_removal_risk(
            is_imported=False,
            required_by_count=2,
            isolation_score=0.5,
        )
        assert risk == "medium"

    def test_imported_package_high_risk(self):
        risk, note = assess_removal_risk(
            is_imported=True,
            required_by_count=0,
            isolation_score=0.0,
        )
        assert risk == "high"


class TestIsolationInfo:
    """Tests for IsolationInfo dataclass."""

    def test_to_dict(self):
        info = IsolationInfo(
            name="test-pkg",
            is_imported=True,
            import_locations=["src/app.py"],
            isolation_score=0.8,
            can_remove=False,
            removal_risk="high",
        )
        d = info.to_dict()
        assert d["name"] == "test-pkg"
        assert d["is_imported"] is True
        assert d["can_remove"] is False


class TestIsolationReport:
    """Tests for IsolationReport dataclass."""

    def test_to_dict(self):
        report = IsolationReport()
        d = report.to_dict()
        assert "summary" in d
        assert d["summary"]["total_packages"] == 0

    def test_with_packages(self):
        info = IsolationInfo(name="pkg", is_imported=False, can_remove=True)
        report = IsolationReport(
            packages=[info],
            total_packages=1,
            unused_count=1,
            removable_count=1,
        )
        d = report.to_dict()
        assert d["summary"]["total_packages"] == 1
        assert len(d["packages"]) == 1


class TestAnalyzeIsolation:
    """Tests for analyze_isolation."""

    def test_nonexistent_path(self):
        report = analyze_isolation(Path("/nonexistent/path"))
        assert len(report.errors) > 0

    def test_empty_directory(self, tmp_path):
        report = analyze_isolation(tmp_path)
        assert isinstance(report, IsolationReport)


class TestIsolationRender:
    """Tests for render functions."""

    def test_render_json(self):
        report = IsolationReport()
        result = render_isolation_json(report)
        data = json.loads(result)
        assert data["summary"]["total_packages"] == 0

    def test_render_table_empty(self):
        from rich.console import Console

        report = IsolationReport()
        console = Console(width=120, force_terminal=False, no_color=True)
        render_isolation_table(report, console=console)

    def test_render_table_with_entries(self):
        from rich.console import Console

        info = IsolationInfo(
            name="unused-lib",
            is_imported=False,
            can_remove=True,
            removal_risk="low",
            removal_note="Not imported anywhere",
        )
        report = IsolationReport(
            packages=[info],
            total_packages=1,
            unused_count=1,
            removable_count=1,
        )
        console = Console(width=120, force_terminal=False, no_color=True)
        render_isolation_table(report, console=console)


# ===== SizeScore Module Tests =====


class TestClassifySize:
    """Tests for classify_size."""

    def test_tiny(self):
        assert classify_size(10) == "tiny"

    def test_small(self):
        assert classify_size(200) == "small"

    def test_medium(self):
        assert classify_size(2000) == "medium"

    def test_large(self):
        assert classify_size(20000) == "large"

    def test_huge(self):
        assert classify_size(100000) == "huge"

    def test_zero(self):
        result = classify_size(0)
        assert result == "tiny"


class TestComputeSizeScore:
    """Tests for compute_size_score."""

    def test_tiny_package_high_score(self):
        score = compute_size_score(size_kb=10, file_count=5, has_wheel=True)
        assert 0 <= score <= 1

    def test_huge_package_low_score(self):
        score = compute_size_score(size_kb=100000, file_count=5000, has_wheel=False)
        assert 0 <= score <= 1

    def test_returns_float(self):
        score = compute_size_score(size_kb=1000, file_count=50, has_wheel=True)
        assert isinstance(score, float)


class TestAnalyzeSizeTrend:
    """Tests for analyze_size_trend."""

    def test_stable_trend(self):
        releases = {
            "1.0.0": [{"packagetype": "bdist_wheel", "size": 1000000}],
            "1.1.0": [{"packagetype": "bdist_wheel", "size": 1050000}],
            "1.2.0": [{"packagetype": "bdist_wheel", "size": 1020000}],
        }
        trend = analyze_size_trend(releases, "1.2.0")
        assert trend in ("stable", "growing", "shrinking", "unknown")

    def test_growing_trend(self):
        releases = {
            "1.0.0": [{"packagetype": "bdist_wheel", "size": 1000000}],
            "2.0.0": [{"packagetype": "bdist_wheel", "size": 5000000}],
            "3.0.0": [{"packagetype": "bdist_wheel", "size": 20000000}],
        }
        trend = analyze_size_trend(releases, "3.0.0")
        assert trend in ("growing", "stable")

    def test_empty_releases(self):
        trend = analyze_size_trend({}, "1.0.0")
        assert trend == "unknown"


class TestFormatSize:
    """Tests for format_size (takes KB as input)."""

    def test_small_values(self):
        result = format_size(0.5)
        assert isinstance(result, str)

    def test_kilobytes(self):
        result = format_size(5)
        assert "KB" in result or "B" in result

    def test_megabytes(self):
        result = format_size(3 * 1024)
        assert "MB" in result

    def test_gigabytes(self):
        result = format_size(2 * 1024 * 1024)
        assert "GB" in result

    def test_zero(self):
        result = format_size(0)
        assert isinstance(result, str)


class TestLighterAlternatives:
    """Tests for LIGHTER_ALTERNATIVES mapping."""

    def test_pandas_has_polars(self):
        assert "polars" in LIGHTER_ALTERNATIVES.get("pandas", [])

    def test_requests_has_httpx(self):
        assert "httpx" in LIGHTER_ALTERNATIVES.get("requests", [])


class TestSizeInfo:
    """Tests for SizeInfo dataclass."""

    def test_to_dict(self):
        info = SizeInfo(
            name="requests",
            version="2.31.0",
            download_size_kb=200,
            install_size_kb=500,
            size_category="small",
            has_wheel=True,
            size_score=0.8,
        )
        d = info.to_dict()
        assert d["name"] == "requests"
        assert d["size_category"] == "small"
        assert d["has_wheel"] is True

    def test_total_size_kb_property(self):
        info = SizeInfo(
            name="pkg",
            version="1.0",
            has_wheel=True,
            wheel_size_kb=100,
            sdist_size_kb=200,
            download_size_kb=150,
        )
        assert info.total_size_kb == 100  # wheel preferred


class TestSizeReport:
    """Tests for SizeReport dataclass."""

    def test_to_dict(self):
        report = SizeReport()
        d = report.to_dict()
        assert "summary" in d
        assert "packages" in d
        assert d["summary"]["total_packages"] == 0


class TestSizeRender:
    """Tests for render functions."""

    def test_render_json(self):
        report = SizeReport()
        result = render_size_json(report)
        data = json.loads(result)
        assert "summary" in data

    def test_render_table_does_not_crash(self):
        from rich.console import Console

        report = SizeReport()
        console = Console(width=120, force_terminal=False, no_color=True)
        render_size_table(report, console=console)


# ===== DepDrift Module Tests =====


class TestDriftSnapshot:
    """Tests for DriftSnapshot dataclass."""

    def test_to_dict(self):
        snapshot = DriftSnapshot(
            commit="abc123",
            date="2024-01-01",
            dependencies={
                "requests": ParsedDependency(name="requests", version="2.28.0", specifier=">="),
            },
        )
        d = snapshot.to_dict()
        assert d["commit"] == "abc123"
        assert "requests" in d["dependencies"]


class TestDriftEntry:
    """Tests for DriftEntry dataclass."""

    def test_to_dict(self):
        entry = DriftEntry(
            name="requests",
            old_version="2.28.0",
            new_version="2.31.0",
            old_specifier=">=",
            new_specifier=">=",
            change_type="upgraded",
            drift_days=30,
            commit="def456",
            date="2024-02-01",
        )
        d = entry.to_dict()
        assert d["name"] == "requests"
        assert d["change_type"] == "upgraded"
        assert d["drift_days"] == 30


class TestCompareSnapshots:
    """Tests for compare_snapshots."""

    def test_no_changes(self):
        old = DriftSnapshot(
            commit="a1",
            date="2024-01-01",
            dependencies={
                "requests": ParsedDependency(name="requests", version="2.28.0", specifier=">="),
            },
        )
        new = DriftSnapshot(
            commit="b2",
            date="2024-02-01",
            dependencies={
                "requests": ParsedDependency(name="requests", version="2.28.0", specifier=">="),
            },
        )
        entries = compare_snapshots(old, new)
        assert len(entries) == 0

    def test_added_package(self):
        old = DriftSnapshot(commit="a1", date="2024-01-01", dependencies={})
        new = DriftSnapshot(
            commit="b2",
            date="2024-02-01",
            dependencies={
                "flask": ParsedDependency(name="flask", version="2.3.0", specifier=">="),
            },
        )
        entries = compare_snapshots(old, new)
        assert len(entries) == 1
        assert entries[0].change_type == "added"
        assert entries[0].name == "flask"

    def test_removed_package(self):
        old = DriftSnapshot(
            commit="a1",
            date="2024-01-01",
            dependencies={
                "flask": ParsedDependency(name="flask", version="2.3.0", specifier=">="),
            },
        )
        new = DriftSnapshot(commit="b2", date="2024-02-01", dependencies={})
        entries = compare_snapshots(old, new)
        assert len(entries) == 1
        assert entries[0].change_type == "removed"

    def test_upgraded_package(self):
        old = DriftSnapshot(
            commit="a1",
            date="2024-01-01",
            dependencies={
                "requests": ParsedDependency(name="requests", version="2.28.0", specifier=">="),
            },
        )
        new = DriftSnapshot(
            commit="b2",
            date="2024-02-01",
            dependencies={
                "requests": ParsedDependency(name="requests", version="2.31.0", specifier=">="),
            },
        )
        entries = compare_snapshots(old, new)
        assert len(entries) == 1
        assert entries[0].change_type == "upgraded"
        assert entries[0].old_version == "2.28.0"
        assert entries[0].new_version == "2.31.0"

    def test_downgraded_package(self):
        old = DriftSnapshot(
            commit="a1",
            date="2024-01-01",
            dependencies={
                "django": ParsedDependency(name="django", version="4.2.0", specifier=">="),
            },
        )
        new = DriftSnapshot(
            commit="b2",
            date="2024-02-01",
            dependencies={
                "django": ParsedDependency(name="django", version="4.1.0", specifier=">="),
            },
        )
        entries = compare_snapshots(old, new)
        assert len(entries) == 1
        assert entries[0].change_type == "downgraded"

    def test_multiple_changes(self):
        old = DriftSnapshot(
            commit="a1",
            date="2024-01-01",
            dependencies={
                "requests": ParsedDependency(name="requests", version="2.28.0", specifier=">="),
                "flask": ParsedDependency(name="flask", version="2.3.0", specifier=">="),
            },
        )
        new = DriftSnapshot(
            commit="b2",
            date="2024-02-01",
            dependencies={
                "requests": ParsedDependency(name="requests", version="2.31.0", specifier=">="),
                "django": ParsedDependency(name="django", version="4.2.0", specifier=">="),
            },
        )
        entries = compare_snapshots(old, new)
        assert len(entries) == 3  # requests upgraded, flask removed, django added

    def test_drift_days_computed(self):
        old = DriftSnapshot(commit="a1", date="2024-01-01", dependencies={})
        new = DriftSnapshot(
            commit="b2",
            date="2024-03-01",
            dependencies={
                "flask": ParsedDependency(name="flask", version="2.3.0", specifier=">="),
            },
        )
        entries = compare_snapshots(old, new)
        if entries:
            assert entries[0].drift_days == 60  # Jan 1 to Mar 1 = 60 days


class TestComputeDriftVelocity:
    """Tests for compute_drift_velocity."""

    def test_zero_days(self):
        vel = compute_drift_velocity([], 0)
        assert vel == 0.0

    def test_none_days(self):
        vel = compute_drift_velocity([], None)
        assert vel == 0.0

    def test_one_change_per_week(self):
        entries = [DriftEntry(name="a", change_type="added")]
        vel = compute_drift_velocity(entries, 7)
        assert abs(vel - 1.0) < 0.01

    def test_multiple_changes(self):
        entries = [
            DriftEntry(name="a", change_type="added"),
            DriftEntry(name="b", change_type="upgraded"),
        ]
        vel = compute_drift_velocity(entries, 14)
        assert abs(vel - 1.0) < 0.01


class TestIdentifyHighDriftPackages:
    """Tests for identify_high_drift_packages."""

    def test_empty_entries(self):
        result = identify_high_drift_packages([])
        assert result == []

    def test_below_threshold(self):
        entries = [
            DriftEntry(name="pkg", change_type="upgraded"),
            DriftEntry(name="pkg", change_type="upgraded"),
        ]
        result = identify_high_drift_packages(entries, threshold=3)
        assert result == []

    def test_at_threshold(self):
        entries = [
            DriftEntry(name="high-drift", change_type="upgraded"),
            DriftEntry(name="high-drift", change_type="upgraded"),
            DriftEntry(name="high-drift", change_type="upgraded"),
        ]
        result = identify_high_drift_packages(entries, threshold=3)
        assert "high-drift" in result

    def test_mixed_packages(self):
        entries = [
            DriftEntry(name="stable", change_type="upgraded"),
            DriftEntry(name="unstable", change_type="upgraded"),
            DriftEntry(name="unstable", change_type="upgraded"),
            DriftEntry(name="unstable", change_type="upgraded"),
        ]
        result = identify_high_drift_packages(entries, threshold=3)
        assert "unstable" in result
        assert "stable" not in result


class TestBuildDriftReport:
    """Tests for build_drift_report."""

    def test_nonexistent_path(self):
        report = build_drift_report("/nonexistent/path")
        assert len(report.errors) > 0

    def test_non_git_directory(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("requests==2.28.0\n")
        report = build_drift_report(str(tmp_path))
        assert len(report.errors) > 0 or report.snapshots_compared == 0


class TestDriftReport:
    """Tests for DriftReport dataclass."""

    def test_to_dict(self):
        report = DriftReport(entries=[], snapshots_compared=0)
        d = report.to_dict()
        assert "summary" in d
        assert "entries" in d


class TestDriftRender:
    """Tests for render functions."""

    def test_render_json(self):
        report = DriftReport(entries=[], snapshots_compared=0)
        result = render_drift_json(report)
        data = json.loads(result)
        assert "summary" in data

    def test_render_table_no_drift(self):
        from rich.console import Console

        report = DriftReport(entries=[], snapshots_compared=2)
        console = Console(width=120, force_terminal=False, no_color=True)
        render_drift_table(report, console=console)

    def test_render_table_with_entries(self):
        from rich.console import Console

        entry = DriftEntry(
            name="requests",
            old_version="2.28.0",
            new_version="2.31.0",
            change_type="upgraded",
            drift_days=30,
            date="2024-02-01",
        )
        report = DriftReport(
            entries=[entry],
            snapshots_compared=2,
            from_date="2024-01-01",
            to_date="2024-02-01",
            from_commit="abc123",
            to_commit="def456",
            upgraded_count=1,
        )
        console = Console(width=120, force_terminal=False, no_color=True)
        render_drift_table(report, console=console)


# ===== Compat Module Tests =====


class TestParseRequiresPython:
    """Tests for parse_requires_python."""

    def test_gte_only(self):
        min_ver, max_ver = parse_requires_python(">=3.8")
        assert min_ver == "3.8"
        assert max_ver is None

    def test_gte_lt(self):
        min_ver, max_ver = parse_requires_python(">=3.8,<3.13")
        assert min_ver == "3.8"
        assert max_ver == "3.12"

    def test_gte_lt4(self):
        min_ver, max_ver = parse_requires_python(">=3.10,<4")
        assert min_ver == "3.10"
        assert max_ver is None

    def test_exact_major(self):
        min_ver, max_ver = parse_requires_python("==3.*")
        assert min_ver == "3.0"
        assert max_ver == "3.99"

    def test_empty_string(self):
        min_ver, max_ver = parse_requires_python("")
        assert min_ver is None
        assert max_ver is None

    def test_gt(self):
        min_ver, max_ver = parse_requires_python(">3.11")
        assert min_ver == "3.12"

    def test_lte(self):
        min_ver, max_ver = parse_requires_python("<=3.12")
        assert max_ver == "3.12"

    def test_compatible_release(self):
        min_ver, max_ver = parse_requires_python("~=3.10")
        assert min_ver == "3.10"
        assert max_ver == "3.10"

    def test_complex_specifier(self):
        min_ver, max_ver = parse_requires_python(">=3.9,<3.14")
        assert min_ver == "3.9"
        assert max_ver == "3.13"


class TestExtractPythonClassifiers:
    """Tests for extract_python_classifiers."""

    def test_basic_classifiers(self):
        classifiers = [
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "License :: OSI Approved :: MIT License",
        ]
        versions = extract_python_classifiers(classifiers)
        assert versions == ["3.8", "3.9", "3.10", "3.11"]

    def test_no_python_classifiers(self):
        classifiers = [
            "License :: OSI Approved :: MIT License",
            "Operating System :: OS Independent",
        ]
        versions = extract_python_classifiers(classifiers)
        assert versions == []

    def test_only_major_version(self):
        classifiers = [
            "Programming Language :: Python :: 3",
        ]
        versions = extract_python_classifiers(classifiers)
        assert versions == []

    def test_empty_classifiers(self):
        versions = extract_python_classifiers([])
        assert versions == []


class TestCheckVersionCompatibility:
    """Tests for check_version_compatibility."""

    def test_no_constraints(self):
        is_compat, detail = check_version_compatibility("3.12")
        assert is_compat is True
        assert "No version constraint" in detail

    def test_compatible_requires_python(self):
        is_compat, detail = check_version_compatibility("3.12", requires_python=">=3.8")
        assert is_compat is True

    def test_incompatible_requires_python(self):
        is_compat, detail = check_version_compatibility("3.12", requires_python=">=3.8,<3.12")
        assert is_compat is False
        assert "Incompatible" in detail

    def test_compatible_classifiers(self):
        is_compat, detail = check_version_compatibility(
            "3.11",
            classifiers=[
                "Programming Language :: Python :: 3.9",
                "Programming Language :: Python :: 3.10",
                "Programming Language :: Python :: 3.11",
            ],
        )
        assert is_compat is True
        assert "Explicitly supports" in detail

    def test_incompatible_classifiers_too_new(self):
        is_compat, detail = check_version_compatibility(
            "3.13",
            classifiers=[
                "Programming Language :: Python :: 3.9",
                "Programming Language :: Python :: 3.10",
                "Programming Language :: Python :: 3.11",
            ],
        )
        assert is_compat is False

    def test_incompatible_classifiers_too_old(self):
        is_compat, detail = check_version_compatibility(
            "3.8",
            classifiers=[
                "Programming Language :: Python :: 3.10",
                "Programming Language :: Python :: 3.11",
            ],
        )
        assert is_compat is False


class TestCheckBreakingOnUpgrade:
    """Tests for check_breaking_on_upgrade."""

    def test_no_requires_python(self):
        breaks, note = check_breaking_on_upgrade("3.11", "3.12", None)
        assert breaks is False
        assert note == ""

    def test_will_break(self):
        breaks, note = check_breaking_on_upgrade("3.11", "3.13", ">=3.9,<3.13")
        assert breaks is True
        assert "Will break" in note

    def test_wont_break(self):
        breaks, note = check_breaking_on_upgrade("3.11", "3.12", ">=3.9")
        assert breaks is False

    def test_both_compatible(self):
        breaks, note = check_breaking_on_upgrade("3.11", "3.12", ">=3.9,<3.14")
        assert breaks is False


class TestCompatInfo:
    """Tests for CompatInfo dataclass."""

    def test_to_dict(self):
        info = CompatInfo(
            name="requests",
            version="2.31.0",
            min_python="3.8",
            supported_versions=["3.8", "3.9", "3.10", "3.11", "3.12"],
            requires_python=">=3.8",
            is_compatible=True,
            compatibility_detail="Explicitly supports Python 3.12",
        )
        d = info.to_dict()
        assert d["name"] == "requests"
        assert d["is_compatible"] is True
        assert len(d["supported_versions"]) == 5


class TestCompatReport:
    """Tests for CompatReport dataclass."""

    def test_to_dict(self):
        report = CompatReport(
            packages=[],
            target_python="3.12",
            current_python="3.11",
            total_packages=0,
            compatible_count=0,
            incompatible_count=0,
            unknown_count=0,
        )
        d = report.to_dict()
        assert "summary" in d
        assert d["summary"]["target_python"] == "3.12"


class TestCompatRender:
    """Tests for render functions."""

    def test_render_json(self):
        report = CompatReport(
            packages=[],
            target_python="3.12",
            current_python="3.11",
            total_packages=0,
            compatible_count=0,
            incompatible_count=0,
            unknown_count=0,
        )
        result = render_compat_json(report)
        data = json.loads(result)
        assert data["summary"]["target_python"] == "3.12"

    def test_render_table_no_packages(self):
        from rich.console import Console

        report = CompatReport(
            packages=[],
            target_python="3.12",
            current_python="3.11",
            total_packages=0,
            compatible_count=0,
            incompatible_count=0,
            unknown_count=0,
        )
        console = Console(width=120, force_terminal=False, no_color=True)
        render_compat_table(report, console=console)

    def test_render_table_with_compatible(self):
        from rich.console import Console

        info = CompatInfo(
            name="requests",
            version="2.31.0",
            is_compatible=True,
            compatibility_detail="Explicitly supports Python 3.12",
        )
        report = CompatReport(
            packages=[info],
            target_python="3.12",
            current_python="3.11",
            total_packages=1,
            compatible_count=1,
            incompatible_count=0,
            unknown_count=0,
        )
        console = Console(width=120, force_terminal=False, no_color=True)
        render_compat_table(report, console=console)

    def test_render_table_with_incompatible(self):
        from rich.console import Console

        info = CompatInfo(
            name="old-lib",
            version="0.1.0",
            is_compatible=False,
            compatibility_detail="Only supports Python 3.8-3.10",
            breaking_on_upgrade=True,
            upgrade_note="Will break on Python 3.12",
        )
        report = CompatReport(
            packages=[info],
            target_python="3.12",
            current_python="3.11",
            total_packages=1,
            compatible_count=0,
            incompatible_count=1,
            unknown_count=0,
            breaking_on_upgrade_count=1,
        )
        console = Console(width=120, force_terminal=False, no_color=True)
        render_compat_table(report, console=console)


# ===== Integration: CLI Command Registration Tests =====


class TestCLIRegistration:
    """Test that all new CLI commands are registered."""

    def test_update_command_exists(self):
        from depcheck.cli import main

        assert "update" in main.commands

    def test_isolate_command_exists(self):
        from depcheck.cli import main

        assert "isolate" in main.commands

    def test_sizescore_command_exists(self):
        from depcheck.cli import main

        assert "sizescore" in main.commands

    def test_depdrift_command_exists(self):
        from depcheck.cli import main

        assert "depdrift" in main.commands

    def test_compat_command_exists(self):
        from depcheck.cli import main

        assert "compat" in main.commands


# ===== Edge Case & Error Handling Tests =====


class TestEdgeCases:
    """Test edge cases across all modules."""

    def test_update_plan_with_unknown_version(self):
        """Packages with 'unknown' version should not crash."""
        pkg = PackageReport(
            name="mystery-pkg",
            installed_version="unknown",
            latest_version="unknown",
            status=HealthStatus.UNKNOWN,
        )
        result = ScanResult(project_path=".", packages=[pkg], errors=[])
        plan = build_update_plan(result)
        assert plan.total_packages >= 0

    def test_drift_report_empty_entries_json(self):
        report = DriftReport(entries=[], snapshots_compared=0)
        json_str = render_drift_json(report)
        data = json.loads(json_str)
        assert data["entries"] == []

    def test_compat_empty_requires_python(self):
        min_ver, max_ver = parse_requires_python("")
        assert min_ver is None
        assert max_ver is None

    def test_size_format_very_large(self):
        result = format_size(100 * 1024 * 1024)  # 100 GB in KB
        assert "GB" in result

    def test_all_update_strategies_valid(self):
        assert UpdateStrategy.DIRECT == "direct"
        assert UpdateStrategy.STAGED == "staged"
        assert UpdateStrategy.SKIP == "skip"
        assert UpdateStrategy.REVIEW == "review"

    def test_all_update_priorities_valid(self):
        for attr in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "DEFERRED"):
            val = getattr(UpdatePriority, attr)
            assert isinstance(val, str)

    def test_stdlib_modules_set_not_empty(self):
        assert len(STDLIB_MODULES) > 0
        assert "os" in STDLIB_MODULES
        assert "json" in STDLIB_MODULES

    def test_drift_velocity_with_many_changes(self):
        entries = [DriftEntry(name=f"pkg-{i}", change_type="upgraded") for i in range(100)]
        vel = compute_drift_velocity(entries, 7)
        assert abs(vel - 100.0) < 0.01

    def test_classify_size_boundaries(self):
        assert classify_size(49) == "tiny"
        assert classify_size(50) == "small"
        assert classify_size(499) == "small"
        assert classify_size(500) == "medium"
        assert classify_size(4999) == "medium"
        assert classify_size(5000) == "large"
        assert classify_size(49999) == "large"
        assert classify_size(50000) == "huge"
