"""Tests for depcheck.bundle — bundled analysis runner."""

from __future__ import annotations

import json
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from depcheck.bundle import (
    BundleCommand,
    BundleReport,
    CommandResult,
    run_bundle,
    render_bundle_json,
    render_bundle_table,
    _run_check,
    _run_audit,
    _run_outdated,
    _run_license,
    _run_size,
    _run_history,
)


# ---------------------------------------------------------------------------
# BundleCommand tests
# ---------------------------------------------------------------------------


class TestBundleCommand:
    """Tests for the BundleCommand enum."""

    def test_values(self) -> None:
        assert BundleCommand.CHECK.value == "check"
        assert BundleCommand.AUDIT.value == "audit"
        assert BundleCommand.OUTDATED.value == "outdated"
        assert BundleCommand.LICENSE.value == "license"
        assert BundleCommand.SIZE.value == "size"
        assert BundleCommand.HISTORY.value == "history"

    def test_all_commands(self) -> None:
        all_cmds = list(BundleCommand)
        assert len(all_cmds) == 6

    def test_from_value(self) -> None:
        assert BundleCommand("check") == BundleCommand.CHECK


# ---------------------------------------------------------------------------
# CommandResult tests
# ---------------------------------------------------------------------------


class TestCommandResult:
    """Tests for the CommandResult dataclass."""

    def test_defaults(self) -> None:
        result = CommandResult(command="check")
        assert result.command == "check"
        assert result.success is True
        assert result.duration_seconds == 0.0
        assert result.summary == ""
        assert result.data == {}
        assert result.error is None

    def test_with_error(self) -> None:
        result = CommandResult(command="audit", success=False, error="audit failed")
        assert result.success is False
        assert result.error == "audit failed"

    def test_to_dict(self) -> None:
        result = CommandResult(
            command="check",
            success=True,
            duration_seconds=1.5,
            summary="Score: 90/100",
            data={"score": 90},
        )
        d = result.to_dict()
        assert d["command"] == "check"
        assert d["success"] is True
        assert d["duration_seconds"] == 1.5
        assert d["summary"] == "Score: 90/100"
        assert d["data"] == {"score": 90}
        assert d["error"] is None

    def test_to_dict_with_error(self) -> None:
        result = CommandResult(
            command="audit",
            success=False,
            error="network error",
        )
        d = result.to_dict()
        assert d["error"] == "network error"
        assert d["success"] is False


# ---------------------------------------------------------------------------
# BundleReport tests
# ---------------------------------------------------------------------------


class TestBundleReport:
    """Tests for the BundleReport dataclass."""

    def _make_report(self, success: bool = True) -> BundleReport:
        results = [
            CommandResult(command="check", success=True, duration_seconds=0.5, summary="Score: 90"),
            CommandResult(command="audit", success=success, duration_seconds=1.0,
                         summary="" if success else "", error="" if success else "fail"),
            CommandResult(command="outdated", success=True, duration_seconds=0.3, summary="3 outdated"),
        ]
        if not success:
            results[1].success = False
            results[1].error = "audit error"
        return BundleReport(
            project_path="/tmp/test",
            commands_run=["check", "audit", "outdated"],
            results=results,
            total_duration_seconds=1.8,
            timestamp="2024-01-15T00:00:00+00:00",
            overall_success=success,
        )

    def test_total_duration(self) -> None:
        report = self._make_report()
        assert report.total_duration_seconds == 1.8

    def test_overall_success_true(self) -> None:
        report = self._make_report(success=True)
        assert report.overall_success is True

    def test_overall_success_false(self) -> None:
        report = self._make_report(success=False)
        assert report.overall_success is False

    def test_commands_run_list(self) -> None:
        report = self._make_report()
        assert report.commands_run == ["check", "audit", "outdated"]

    def test_empty_report(self) -> None:
        report = BundleReport(project_path="/tmp")
        assert report.overall_success is True
        assert len(report.results) == 0

    def test_to_dict(self) -> None:
        report = self._make_report()
        d = report.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert d["total_duration_seconds"] == 1.8
        assert d["commands_run"] == ["check", "audit", "outdated"]
        assert d["overall_success"] is True
        assert len(d["results"]) == 3

    def test_to_dict_with_errors(self) -> None:
        report = BundleReport(
            project_path="/tmp",
            errors=["something broke"],
            overall_success=False,
        )
        d = report.to_dict()
        assert d["errors"] == ["something broke"]


# ---------------------------------------------------------------------------
# Individual command runner tests
# ---------------------------------------------------------------------------


class TestRunCheck:
    """Tests for _run_check."""

    def test_check_returns_result(self) -> None:
        """Test that _run_check returns a CommandResult."""
        mock_report = MagicMock()
        mock_report.overall_score = 85
        mock_report.overall_grade = MagicMock(value="B")
        mock_report.categories = []

        with patch("depcheck.check.run_check", return_value=mock_report):
            result = _run_check("/tmp/test")
            assert isinstance(result, CommandResult)
            assert result.command == "check"
            assert result.success is True
            assert "85" in result.summary

    def test_check_handles_exception(self) -> None:
        with patch("depcheck.check.run_check", side_effect=Exception("boom")):
            result = _run_check("/tmp/test")
            assert result.success is False
            assert "boom" in (result.error or "")


class TestRunAudit:
    """Tests for _run_audit."""

    def test_returns_result(self) -> None:
        mock_report = MagicMock()
        mock_report.risk_level = MagicMock(value="low")
        mock_report.all_risks = []

        with patch("depcheck.audit.run_audit", return_value=mock_report):
            result = _run_audit("/tmp/test")
            assert isinstance(result, CommandResult)
            assert result.command == "audit"
            assert result.success is True

    def test_handles_exception(self) -> None:
        with patch("depcheck.audit.run_audit", side_effect=Exception("err")):
            result = _run_audit("/tmp/test")
            assert result.success is False


class TestRunOutdated:
    """Tests for _run_outdated."""

    def test_returns_result(self) -> None:
        mock_scan = MagicMock()
        mock_outdated = MagicMock()
        mock_outdated.outdated_count = 3
        mock_outdated.major_count = 1
        mock_outdated.minor_count = 1
        mock_outdated.patch_count = 1
        mock_outdated.up_to_date_count = 5

        with patch("depcheck.scanner.scan_project", return_value=mock_scan), \
             patch("depcheck.outdated.build_outdated_report", return_value=mock_outdated):
            result = _run_outdated("/tmp/test")
            assert result.command == "outdated"
            assert result.success is True
            assert "3" in result.summary


class TestRunLicense:
    """Tests for _run_license."""

    def test_returns_result(self) -> None:
        mock_scan = MagicMock()
        mock_scan.packages = []
        mock_scan.total = 0

        with patch("depcheck.scanner.scan_project", return_value=mock_scan):
            result = _run_license("/tmp/test")
            assert result.command == "license"
            assert result.success is True


class TestRunSize:
    """Tests for _run_size."""

    def test_returns_result(self) -> None:
        mock_report = MagicMock()
        mock_report.total_mb = 10.5
        mock_report.total_file_count = 100
        mock_report.packages = []

        with patch("depcheck.size.analyze_sizes", return_value=mock_report):
            result = _run_size("/tmp/test")
            assert result.command == "size"
            assert result.success is True

    def test_handles_exception(self) -> None:
        with patch("depcheck.size.analyze_sizes", side_effect=Exception("err")):
            result = _run_size("/tmp/test")
            assert result.success is False


class TestRunHistory:
    """Tests for _run_history."""

    def test_returns_result(self) -> None:
        mock_report = MagicMock()
        mock_report.accelerating_count = 1
        mock_report.steady_count = 2
        mock_report.slowing_count = 0
        mock_report.abandoned_count = 0
        mock_report.avg_current_version_age = 50.0

        with patch("depcheck.history.analyze_history", return_value=mock_report):
            result = _run_history("/tmp/test")
            assert result.command == "history"
            assert result.success is True

    def test_handles_exception(self) -> None:
        with patch("depcheck.history.analyze_history", side_effect=Exception("err")):
            result = _run_history("/tmp/test")
            assert result.success is False


# ---------------------------------------------------------------------------
# run_bundle integration tests
# ---------------------------------------------------------------------------


class TestRunBundle:
    """Integration tests for run_bundle."""

    def test_invalid_path(self) -> None:
        report = run_bundle("/nonexistent/path")
        assert report.overall_success is False
        assert len(report.errors) > 0

    def test_default_commands(self, tmp_path) -> None:
        """Test that default bundle runs check, audit, outdated."""
        mock_result = CommandResult(command="check", success=True, duration_seconds=0.1)
        with patch("depcheck.bundle.COMMAND_RUNNERS") as mock_runners:
            mock_runners.get.side_effect = lambda cmd: MagicMock(return_value=mock_result)
            report = run_bundle(str(tmp_path))
            assert report.commands_run == ["check", "audit", "outdated"]
            assert len(report.results) == 3

    def test_custom_commands(self, tmp_path) -> None:
        """Test custom command selection."""
        mock_result = CommandResult(command="license", success=True, duration_seconds=0.1)
        with patch("depcheck.bundle.COMMAND_RUNNERS") as mock_runners:
            mock_runners.get.side_effect = lambda cmd: MagicMock(return_value=mock_result)
            report = run_bundle(
                str(tmp_path),
                commands=[BundleCommand.LICENSE, BundleCommand.SIZE],
            )
            assert report.commands_run == ["license", "size"]
            assert len(report.results) == 2

    def test_all_commands(self, tmp_path) -> None:
        """Test running all commands."""
        mock_result = CommandResult(command="x", success=True, duration_seconds=0.1)
        with patch("depcheck.bundle.COMMAND_RUNNERS") as mock_runners:
            mock_runners.get.side_effect = lambda cmd: MagicMock(return_value=mock_result)
            report = run_bundle(str(tmp_path), commands=list(BundleCommand))
            assert report.commands_run == ["check", "audit", "outdated", "license", "size", "history"]
            assert len(report.results) == 6

    def test_mixed_success_failure(self, tmp_path) -> None:
        """Test that one failure makes overall_success False."""
        results_iter = iter([
            CommandResult(command="check", success=True, duration_seconds=0.1),
            CommandResult(command="audit", success=False, error="fail", duration_seconds=0.1),
            CommandResult(command="outdated", success=True, duration_seconds=0.1),
        ])
        mock_runner = MagicMock(side_effect=lambda path: next(results_iter))
        with patch("depcheck.bundle.COMMAND_RUNNERS") as mock_runners:
            mock_runners.get.return_value = mock_runner
            report = run_bundle(str(tmp_path))
            assert report.overall_success is False

    def test_timestamp_set(self, tmp_path) -> None:
        """Test that the report has a timestamp."""
        with patch("depcheck.bundle._run_check") as mc:
            mc.return_value = CommandResult(command="check", success=True)
            report = run_bundle(str(tmp_path), commands=[BundleCommand.CHECK])
            assert report.timestamp != ""


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


class TestRenderBundleTable:
    """Tests for render_bundle_table."""

    def test_renders_without_error(self) -> None:
        from rich.console import Console

        report = BundleReport(
            project_path="/tmp/test",
            commands_run=["check", "audit"],
            results=[
                CommandResult(command="check", success=True, duration_seconds=0.5, summary="Score: 90"),
                CommandResult(command="audit", success=True, duration_seconds=1.0, summary="No vulns"),
            ],
            total_duration_seconds=1.5,
            timestamp="2024-01-15T00:00:00Z",
            overall_success=True,
        )
        console = Console(file=StringIO(), width=120)
        render_bundle_table(report, console=console)

    def test_renders_with_failures(self) -> None:
        from rich.console import Console

        report = BundleReport(
            project_path="/tmp/test",
            commands_run=["check", "audit"],
            results=[
                CommandResult(command="check", success=True, duration_seconds=0.5, summary="OK"),
                CommandResult(command="audit", success=False, error="fail", duration_seconds=1.0),
            ],
            total_duration_seconds=1.5,
            timestamp="2024-01-15T00:00:00Z",
            overall_success=False,
        )
        console = Console(file=StringIO(), width=120)
        render_bundle_table(report, console=console)

    def test_renders_empty(self) -> None:
        from rich.console import Console

        report = BundleReport(project_path="/tmp/test")
        console = Console(file=StringIO(), width=120)
        render_bundle_table(report, console=console)


class TestRenderBundleJson:
    """Tests for render_bundle_json."""

    def test_produces_valid_json(self) -> None:
        from rich.console import Console

        report = BundleReport(
            project_path="/tmp/test",
            commands_run=["check"],
            results=[
                CommandResult(command="check", success=True, duration_seconds=0.5, summary="OK"),
            ],
            total_duration_seconds=0.5,
            timestamp="2024-01-15T00:00:00Z",
            overall_success=True,
        )
        buf = StringIO()
        console = Console(file=buf, width=1000, force_terminal=False, no_color=True)
        render_bundle_json(report, console=console)
        data = json.loads(buf.getvalue())
        assert data["overall_success"] is True
        assert data["commands_run"] == ["check"]
        assert len(data["results"]) == 1
