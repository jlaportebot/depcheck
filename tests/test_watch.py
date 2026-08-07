"""Tests for the depcheck watch module."""

from __future__ import annotations

import datetime
import time
from pathlib import Path

import pytest

from depcheck.models import HealthStatus, PackageReport, ScanResult
from depcheck.watch import (
    DEFAULT_WATCH_PATTERNS,
    ScanRecord,
    StatusChange,
    WatchConfig,
    WatchState,
    detect_changes,
    diff_scan_results,
    discover_watched_files,
    get_file_mtimes,
    render_watch_dashboard,
)

# --- Fixtures ---


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project directory with dependency files."""
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nrich>=13.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "test"\ndependencies = ["click>=8.0"]\n'
    )
    return tmp_path


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Create a sample scan result with mixed health statuses."""
    return ScanResult(
        project_path="/tmp/test_project",
        packages=[
            PackageReport(
                name="requests",
                installed_version="2.31.0",
                latest_version="2.32.0",
                status=HealthStatus.OUTDATED,
            ),
            PackageReport(
                name="rich",
                installed_version="13.7.0",
                latest_version="13.7.0",
                status=HealthStatus.HEALTHY,
            ),
            PackageReport(
                name="click",
                installed_version="8.1.7",
                latest_version="8.1.7",
                status=HealthStatus.HEALTHY,
            ),
        ],
        files_scanned=["/tmp/test_project/requirements.txt"],
    )


@pytest.fixture
def sample_config(tmp_project: Path) -> WatchConfig:
    """Create a sample watch configuration."""
    return WatchConfig(
        project_path=str(tmp_project),
        debounce_seconds=0.1,
        poll_interval=0.05,
    )


# --- WatchConfig tests ---


class TestWatchConfig:
    def test_default_values(self):
        config = WatchConfig()
        assert config.project_path == "."
        assert config.debounce_seconds == 2.0
        assert config.poll_interval == 1.0
        assert config.check_vulnerabilities is True
        assert config.check_licenses is False
        assert config.exit_on_issue is False
        assert config.fail_on is None
        assert config.show_history is True
        assert config.max_history == 20
        assert len(config.watch_patterns) > 0

    def test_custom_values(self):
        config = WatchConfig(
            project_path="/my/project",
            debounce_seconds=5.0,
            poll_interval=2.0,
            check_vulnerabilities=False,
            exit_on_issue=True,
            fail_on="vulnerable",
            max_history=50,
        )
        assert config.project_path == "/my/project"
        assert config.debounce_seconds == 5.0
        assert config.poll_interval == 2.0
        assert config.check_vulnerabilities is False
        assert config.exit_on_issue is True
        assert config.fail_on == "vulnerable"
        assert config.max_history == 50


# --- StatusChange tests ---


class TestStatusChange:
    def test_worsening_change(self):
        change = StatusChange(
            package_name="requests",
            old_status="healthy",
            new_status="vulnerable",
        )
        assert change.is_worsening is True
        assert change.is_improvement is False

    def test_improvement_change(self):
        change = StatusChange(
            package_name="requests",
            old_status="vulnerable",
            new_status="healthy",
        )
        assert change.is_worsening is False
        assert change.is_improvement is True

    def test_same_status(self):
        change = StatusChange(
            package_name="requests",
            old_status="healthy",
            new_status="healthy",
        )
        assert change.is_worsening is False
        assert change.is_improvement is False

    def test_to_dict(self):
        change = StatusChange(
            package_name="requests",
            old_status="healthy",
            new_status="outdated",
            details="version: 2.31.0 → 2.32.0",
        )
        d = change.to_dict()
        assert d["package"] == "requests"
        assert d["old_status"] == "healthy"
        assert d["new_status"] == "outdated"
        assert d["details"] == "version: 2.31.0 → 2.32.0"

    def test_severity_ordering(self):
        """Verify severity ordering: healthy < outdated < unmaintained
        < yanked < vulnerable < removed."""
        changes = [
            ("healthy", "outdated", True),
            ("healthy", "vulnerable", True),
            ("outdated", "vulnerable", True),
            ("vulnerable", "healthy", False),
            ("outdated", "healthy", False),
            ("unmaintained", "yanked", True),
            ("yanked", "removed", True),
        ]
        for old, new, expected_worsening in changes:
            change = StatusChange(package_name="pkg", old_status=old, new_status=new)
            assert change.is_worsening == expected_worsening, (
                f"Expected {old} → {new} worsening={expected_worsening}"
            )


# --- ScanRecord tests ---


class TestScanRecord:
    def test_basic_record(self):
        record = ScanRecord(
            timestamp=datetime.datetime(2024, 1, 1, 12, 0, 0),
            trigger="initial",
            total_packages=5,
            issues_count=2,
        )
        assert record.trigger == "initial"
        assert record.total_packages == 5
        assert record.issues_count == 2
        assert record.status_changes == []

    def test_to_dict(self):
        record = ScanRecord(
            timestamp=datetime.datetime(2024, 1, 1, 12, 0, 0),
            trigger="file_change",
            trigger_file="requirements.txt",
            duration_seconds=1.5,
            total_packages=10,
            issues_count=3,
        )
        d = record.to_dict()
        assert d["trigger"] == "file_change"
        assert d["trigger_file"] == "requirements.txt"
        assert d["duration_seconds"] == 1.5
        assert d["total_packages"] == 10
        assert d["issues_count"] == 3


# --- File discovery tests ---


class TestDiscoverWatchedFiles:
    def test_finds_requirements_txt(self, tmp_project: Path):
        files = discover_watched_files(tmp_project, DEFAULT_WATCH_PATTERNS)
        names = [f.name for f in files]
        assert "requirements.txt" in names

    def test_finds_pyproject_toml(self, tmp_project: Path):
        files = discover_watched_files(tmp_project, DEFAULT_WATCH_PATTERNS)
        names = [f.name for f in files]
        assert "pyproject.toml" in names

    def test_empty_directory(self, tmp_path: Path):
        files = discover_watched_files(tmp_path, DEFAULT_WATCH_PATTERNS)
        assert files == []

    def test_custom_pattern(self, tmp_path: Path):
        (tmp_path / "custom.deps").write_text("requests\n")
        files = discover_watched_files(tmp_path, ["custom.deps"])
        assert len(files) == 1
        assert files[0].name == "custom.deps"

    def test_glob_patterns(self, tmp_path: Path):
        (tmp_path / "requirements.txt").write_text("requests\n")
        (tmp_path / "requirements-dev.txt").write_text("pytest\n")
        (tmp_path / "requirements-test.txt").write_text("coverage\n")
        files = discover_watched_files(tmp_path, ["requirements*.txt"])
        names = [f.name for f in files]
        assert "requirements.txt" in names
        assert "requirements-dev.txt" in names
        assert "requirements-test.txt" in names

    def test_no_subdirectory_search(self, tmp_path: Path):
        """Watch patterns should only match in the project root, not subdirectories."""
        (tmp_path / "requirements.txt").write_text("requests\n")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "requirements.txt").write_text("should-not-match\n")
        files = discover_watched_files(tmp_path, ["requirements.txt"])
        assert len(files) == 1
        assert files[0].parent == tmp_path

    def test_deduplication(self, tmp_path: Path):
        """Overlapping patterns should not return duplicate files."""
        (tmp_path / "requirements.txt").write_text("requests\n")
        files = discover_watched_files(tmp_path, ["requirements.txt", "requirements*.txt"])
        names = [f.name for f in files]
        assert names.count("requirements.txt") == 1


# --- File mtime tests ---


class TestGetFileMtimes:
    def test_returns_mtimes(self, tmp_project: Path):
        files = discover_watched_files(tmp_project, DEFAULT_WATCH_PATTERNS)
        mtimes = get_file_mtimes(files)
        assert len(mtimes) == 2  # requirements.txt + pyproject.toml
        for path_str, mtime in mtimes.items():
            assert mtime > 0

    def test_missing_file(self, tmp_path: Path):
        nonexistent = tmp_path / "does_not_exist.txt"
        mtimes = get_file_mtimes([nonexistent])
        assert len(mtimes) == 0  # OSError caught silently


class TestDetectChanges:
    def test_no_changes(self):
        old = {"/a/req.txt": 1000.0}
        new = {"/a/req.txt": 1000.0}
        assert detect_changes(old, new) == []

    def test_modified_file(self):
        old = {"/a/req.txt": 1000.0}
        new = {"/a/req.txt": 2000.0}
        changes = detect_changes(old, new)
        assert len(changes) == 1
        assert changes[0] == "/a/req.txt"

    def test_new_file(self):
        old = {"/a/req.txt": 1000.0}
        new = {"/a/req.txt": 1000.0, "/a/pyproject.toml": 1500.0}
        changes = detect_changes(old, new)
        assert len(changes) == 1
        assert "/a/pyproject.toml" in changes

    def test_deleted_file(self):
        old = {"/a/req.txt": 1000.0, "/a/pyproject.toml": 1500.0}
        new = {"/a/req.txt": 1000.0}
        changes = detect_changes(old, new)
        assert len(changes) == 1
        assert "/a/pyproject.toml" in changes

    def test_multiple_changes(self):
        old = {"/a/req.txt": 1000.0, "/a/pyproject.toml": 1500.0}
        new = {"/a/req.txt": 2000.0, "/a/pipfile": 3000.0}
        changes = detect_changes(old, new)
        assert len(changes) == 3  # req modified, pyproject deleted, pipfile new


# --- Scan diff tests ---


class TestDiffScanResults:
    def test_no_changes(self, sample_scan_result: ScanResult):
        changes = diff_scan_results(sample_scan_result, sample_scan_result)
        assert changes == []

    def test_status_change(self, sample_scan_result: ScanResult):
        new_result = ScanResult(
            project_path="/tmp/test_project",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.32.0",
                    status=HealthStatus.VULNERABLE,  # Changed from OUTDATED
                ),
                PackageReport(
                    name="rich",
                    installed_version="13.7.0",
                    latest_version="13.7.0",
                    status=HealthStatus.HEALTHY,
                ),
                PackageReport(
                    name="click",
                    installed_version="8.1.7",
                    latest_version="8.1.7",
                    status=HealthStatus.HEALTHY,
                ),
            ],
        )
        changes = diff_scan_results(sample_scan_result, new_result)
        assert len(changes) == 1
        assert changes[0].package_name == "requests"
        assert changes[0].old_status == "outdated"
        assert changes[0].new_status == "vulnerable"
        assert changes[0].is_worsening is True

    def test_new_package(self, sample_scan_result: ScanResult):
        new_result = ScanResult(
            project_path="/tmp/test_project",
            packages=[
                *sample_scan_result.packages,
                PackageReport(
                    name="flask",
                    installed_version="3.0.0",
                    status=HealthStatus.HEALTHY,
                ),
            ],
        )
        changes = diff_scan_results(sample_scan_result, new_result)
        assert len(changes) == 1
        assert changes[0].package_name == "flask"
        assert changes[0].old_status == "(new)"

    def test_removed_package(self, sample_scan_result: ScanResult):
        new_result = ScanResult(
            project_path="/tmp/test_project",
            packages=[p for p in sample_scan_result.packages if p.name != "click"],
        )
        changes = diff_scan_results(sample_scan_result, new_result)
        assert len(changes) == 1
        assert changes[0].package_name == "click"
        assert changes[0].new_status == "(removed)"

    def test_improvement(self, sample_scan_result: ScanResult):
        new_result = ScanResult(
            project_path="/tmp/test_project",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.32.0",
                    latest_version="2.32.0",
                    status=HealthStatus.HEALTHY,  # Improved from OUTDATED
                ),
                PackageReport(
                    name="rich",
                    installed_version="13.7.0",
                    latest_version="13.7.0",
                    status=HealthStatus.HEALTHY,
                ),
                PackageReport(
                    name="click",
                    installed_version="8.1.7",
                    latest_version="8.1.7",
                    status=HealthStatus.HEALTHY,
                ),
            ],
        )
        changes = diff_scan_results(sample_scan_result, new_result)
        assert len(changes) == 1
        assert changes[0].is_improvement is True
        assert changes[0].is_worsening is False

    def test_multiple_changes(self, sample_scan_result: ScanResult):
        new_result = ScanResult(
            project_path="/tmp/test_project",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.31.0",
                    latest_version="2.32.0",
                    status=HealthStatus.VULNERABLE,  # Worsened
                ),
                PackageReport(
                    name="rich",
                    installed_version="13.7.0",
                    latest_version="13.7.0",
                    status=HealthStatus.UNMAINTAINED,  # Worsened
                ),
                # click removed
                PackageReport(
                    name="flask",
                    installed_version="3.0.0",
                    status=HealthStatus.HEALTHY,  # New
                ),
            ],
        )
        changes = diff_scan_results(sample_scan_result, new_result)
        assert len(changes) == 4  # requests worsened, rich worsened, click removed, flask new

    def test_version_change_details(self, sample_scan_result: ScanResult):
        new_result = ScanResult(
            project_path="/tmp/test_project",
            packages=[
                PackageReport(
                    name="requests",
                    installed_version="2.32.0",  # Version changed
                    latest_version="2.33.0",  # Latest changed
                    status=HealthStatus.HEALTHY,
                ),
                PackageReport(
                    name="rich",
                    installed_version="13.7.0",
                    latest_version="13.7.0",
                    status=HealthStatus.HEALTHY,
                ),
                PackageReport(
                    name="click",
                    installed_version="8.1.7",
                    latest_version="8.1.7",
                    status=HealthStatus.HEALTHY,
                ),
            ],
        )
        changes = diff_scan_results(sample_scan_result, new_result)
        assert len(changes) == 1
        assert "version" in changes[0].details.lower()


# --- Dashboard rendering tests ---


class TestRenderWatchDashboard:
    def test_renders_without_error(
        self, sample_config: WatchConfig, sample_scan_result: ScanResult
    ):
        state = WatchState(config=sample_config)
        state.last_scan_result = sample_scan_result
        state.total_scans = 1
        state.last_trigger = "initial"
        state.watched_files = ["requirements.txt", "pyproject.toml"]
        state.scan_history.append(
            ScanRecord(
                timestamp=datetime.datetime.now(),
                trigger="initial",
                total_packages=3,
                issues_count=1,
                duration_seconds=0.5,
            )
        )
        panel = render_watch_dashboard(state)
        assert panel is not None

    def test_renders_with_no_scan(self, sample_config: WatchConfig):
        state = WatchState(config=sample_config)
        panel = render_watch_dashboard(state)
        assert panel is not None

    def test_renders_with_changes(self, sample_config: WatchConfig, sample_scan_result: ScanResult):
        state = WatchState(config=sample_config)
        state.last_scan_result = sample_scan_result
        state.total_scans = 2
        state.total_changes_detected = 1
        state.last_trigger = "file_change"
        state.watched_files = ["requirements.txt"]
        state.scan_history.append(
            ScanRecord(
                timestamp=datetime.datetime.now(),
                trigger="file_change",
                trigger_file="requirements.txt",
                total_packages=3,
                issues_count=1,
                status_changes=[
                    StatusChange("requests", "healthy", "vulnerable", "1 vulnerability"),
                ],
            )
        )
        panel = render_watch_dashboard(state, changed_files=["/tmp/requirements.txt"])
        assert panel is not None


# --- WatchState tests ---


class TestWatchState:
    def test_default_state(self, sample_config: WatchConfig):
        state = WatchState(config=sample_config)
        assert state.last_scan_result is None
        assert state.total_scans == 0
        assert state.total_changes_detected == 0
        assert state.is_running is True

    def test_history_trimming(self, sample_config: WatchConfig):
        state = WatchState(config=sample_config)
        sample_config.max_history = 3
        for i in range(5):
            state.scan_history.append(
                ScanRecord(
                    timestamp=datetime.datetime.now(),
                    trigger="initial",
                    total_packages=i,
                    issues_count=0,
                )
            )
            if len(state.scan_history) > sample_config.max_history:
                state.scan_history = state.scan_history[-sample_config.max_history :]
        assert len(state.scan_history) == 3


# --- Integration: scan + diff ---


class TestWatchIntegration:
    def test_scan_record_creation(self, tmp_project: Path):
        """Test that a ScanRecord is properly created from a real scan."""
        from depcheck.watch import run_scan

        config = WatchConfig(
            project_path=str(tmp_project),
            check_vulnerabilities=False,  # Skip for speed
        )
        result, record = run_scan(config, trigger="test")
        assert isinstance(result, ScanResult)
        assert isinstance(record, ScanRecord)
        assert record.trigger == "test"
        assert record.duration_seconds >= 0

    def test_watch_discovers_files(self, tmp_project: Path):
        """Test that watch discovers the right dependency files."""
        from depcheck.watch import DEFAULT_WATCH_PATTERNS, discover_watched_files

        files = discover_watched_files(tmp_project, DEFAULT_WATCH_PATTERNS)
        names = {f.name for f in files}
        assert "requirements.txt" in names
        assert "pyproject.toml" in names

    def test_file_change_detection(self, tmp_project: Path):
        """Test that file modifications are detected."""
        from depcheck.watch import (
            DEFAULT_WATCH_PATTERNS,
            detect_changes,
            discover_watched_files,
            get_file_mtimes,
        )

        files = discover_watched_files(tmp_project, DEFAULT_WATCH_PATTERNS)
        old_mtimes = get_file_mtimes(files)

        # Modify a file
        time.sleep(0.1)
        req_file = tmp_project / "requirements.txt"
        req_file.write_text("requests==2.32.0\nrich>=13.0\nflask\n")

        new_mtimes = get_file_mtimes(files)
        changes = detect_changes(old_mtimes, new_mtimes)
        assert len(changes) >= 1
        assert any("requirements.txt" in c for c in changes)


# --- CLI integration tests ---


class TestWatchCLI:
    def test_watch_command_exists(self):
        """Test that the watch command is registered."""
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["watch", "--help"])
        assert result.exit_code == 0
        assert "Watch a project for dependency changes" in result.output

    def test_watch_help_shows_options(self):
        """Test that all watch options appear in help."""
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["watch", "--help"])
        assert "--debounce" in result.output
        assert "--poll-interval" in result.output
        assert "--no-vuln-check" in result.output
        assert "--check-licenses" in result.output
        assert "--exit-on-issue" in result.output
        assert "--fail-on" in result.output
        assert "--no-history" in result.output
