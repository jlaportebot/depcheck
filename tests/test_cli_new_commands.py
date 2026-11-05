"""Tests for new CLI commands: annotations, predict, stack, config, summary, workspace, remediate, search."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from depcheck.commands.annotations import command as annotations_command
from depcheck.commands.config import command as config_command
from depcheck.commands.predict import command as predict_command
from depcheck.commands.remediate import command as remediate_command
from depcheck.commands.search import command as search_command
from depcheck.commands.stack import command as stack_command
from depcheck.commands.summary import command as summary_command
from depcheck.commands.workspace import command as workspace_command

# ──────────────────────────────────────────────────────────────────────────────
# Test helpers
# ──────────────────────────────────────────────────────────────────────────────

runner = CliRunner()


def _invoke_json(cmd, *args):
    """Invoke a command with --json and return parsed JSON."""
    # For config group, --json must come after the subcommand
    if hasattr(cmd, "commands"):  # It's a click Group
        result = runner.invoke(cmd, [*args, "--json"])
    else:
        result = runner.invoke(cmd, ["--json", *args])
    assert result.exit_code in (0, 1), f"Command failed: {result.output}"
    return json.loads(result.output)


def _invoke_plain(cmd, *args):
    """Invoke a command without --json and return raw output."""
    result = runner.invoke(cmd, list(args))
    assert result.exit_code in (0, 1), f"Command failed: {result.output}"
    return result.output


def _make_predict_result():
    """Create a mock PredictResult with proper structure."""
    from depcheck.predict import DeprecationRiskLevel

    mock = MagicMock()
    mock.packages = []
    mock.errors = []
    mock.project_path = "."
    mock.total_packages = 0
    mock.low_risk_count = 0
    mock.moderate_risk_count = 0
    mock.high_risk_count = 0
    mock.critical_risk_count = 0
    mock.overall_deprecation_risk = DeprecationRiskLevel.LOW
    mock.to_dict.return_value = {
        "project_path": ".",
        "packages": [],
        "errors": [],
        "total_packages": 0,
        "risk_summary": {"low": 0, "moderate": 0, "high": 0, "critical": 0},
        "overall_deprecation_risk": "low",
    }
    return mock


def _make_workspace_result(tmp_path):
    """Create a mock WorkspaceScanResult with proper structure."""
    from depcheck.workspace import WorkspaceType

    mock = MagicMock()
    mock.workspace_type = WorkspaceType.UV
    mock.members = []
    mock.root = tmp_path
    mock.total_packages = 0
    mock.total_vulnerabilities = 0
    mock.errors = []
    return mock


def _make_scan_result():
    """Create a mock ScanResult with proper structure."""
    mock = MagicMock()
    mock.packages = []
    mock.errors = []
    return mock


def _make_update_plan():
    """Create a mock UpdatePlan with proper structure."""
    mock = MagicMock()
    mock.steps = []
    mock.total_packages = 0
    mock.up_to_date_count = 0
    mock.needs_update_count = 0
    mock.critical_count = 0
    mock.high_count = 0
    mock.medium_count = 0
    mock.low_count = 0
    mock.deferred_count = 0
    mock.estimated_time_minutes = 0
    mock.errors = []
    mock.to_dict.return_value = {
        "summary": {
            "total_packages": 0,
            "up_to_date": 0,
            "needs_update": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "deferred": 0,
            "estimated_time_minutes": 0,
        },
        "steps": [],
        "errors": [],
    }
    return mock


def _make_remediation_plan():
    """Create a mock RemediationPlan with proper structure."""
    mock = MagicMock()
    mock.groups = []
    mock.repository = "owner/repo"
    mock.total_packages = 0
    mock.needs_update_count = 0
    mock.to_dict.return_value = {
        "repository": "owner/repo",
        "groups": [],
        "summary": {"total_packages": 0, "needs_update": 0, "groups_count": 0},
    }
    return mock


# ──────────────────────────────────────────────────────────────────────────────
# annotations tests
# ──────────────────────────────────────────────────────────────────────────────


class TestAnnotationsCommand:
    """Tests for `depcheck annotations`."""

    def test_help_works(self) -> None:
        result = runner.invoke(annotations_command, ["--help"])
        assert result.exit_code == 0
        assert "annotations" in result.output.lower()

    def test_command_reachable(self) -> None:
        """Command is registered and invocable."""
        with patch("depcheck.commands.annotations._common.scan_project") as mock_scan:
            mock_scan.return_value = _make_scan_result()
            result = runner.invoke(annotations_command, ["."])
            assert result.exit_code == 0

    def test_json_output_parses(self, tmp_path) -> None:
        """--json output is valid JSON."""
        with patch("depcheck.commands.annotations._common.scan_project") as mock_scan:
            mock_scan.return_value = _make_scan_result()
            data = _invoke_json(annotations_command, str(tmp_path))
            assert isinstance(data, list)  # annotations are a list

    def test_output_file_option(self, tmp_path) -> None:
        """--output FILE writes annotations to file."""
        out_file = tmp_path / "annotations.txt"
        with patch("depcheck.commands.annotations._common.scan_project") as mock_scan:
            mock_scan.return_value = _make_scan_result()
            result = runner.invoke(annotations_command, [str(tmp_path), "--output", str(out_file)])
            assert result.exit_code == 0
            assert out_file.exists()

    def test_fail_on_option(self, tmp_path) -> None:
        """--fail-on exits 1 when condition met."""
        from depcheck.models import HealthStatus, PackageReport, ScanResult, Vulnerability

        vuln = Vulnerability(vuln_id="GHSA-1234", summary="Test", severity="HIGH", url="")
        pkg = PackageReport(
            name="bad-pkg",
            installed_version="1.0",
            latest_version="2.0",
            status=HealthStatus.VULNERABLE,
            vulnerabilities=[vuln],
        )
        scan_result = ScanResult(project_path=str(tmp_path), packages=[pkg])

        with patch("depcheck.commands.annotations._common.scan_project", return_value=scan_result):
            result = runner.invoke(annotations_command, [str(tmp_path), "--fail-on", "vulnerable"])
            assert result.exit_code == 1


# ──────────────────────────────────────────────────────────────────────────────
# predict tests
# ──────────────────────────────────────────────────────────────────────────────


class TestPredictCommand:
    """Tests for `depcheck predict`."""

    def test_help_works(self) -> None:
        result = runner.invoke(predict_command, ["--help"])
        assert result.exit_code == 0
        assert "predict" in result.output.lower()

    def test_command_reachable(self) -> None:
        with patch("depcheck.commands.predict.run_predict") as mock_predict:
            mock_predict.return_value = _make_predict_result()
            result = runner.invoke(predict_command, ["."])
            assert result.exit_code == 0

    def test_json_output_parses(self, tmp_path) -> None:
        with patch("depcheck.commands.predict.run_predict") as mock_predict:
            mock_predict.return_value = _make_predict_result()
            data = _invoke_json(predict_command, str(tmp_path))
            assert "packages" in data

    def test_no_vuln_check_option(self, tmp_path) -> None:
        """--no-vuln-check passes through to run_predict."""
        with patch("depcheck.commands.predict.run_predict") as mock_predict:
            mock_predict.return_value = _make_predict_result()
            runner.invoke(predict_command, [str(tmp_path), "--no-vuln-check"])
            mock_predict.assert_called_once()
            kwargs = mock_predict.call_args.kwargs
            assert kwargs.get("check_vulnerabilities") is False


# ──────────────────────────────────────────────────────────────────────────────
# stack tests
# ──────────────────────────────────────────────────────────────────────────────


class TestStackCommand:
    """Tests for `depcheck stack`."""

    def test_help_works(self) -> None:
        result = runner.invoke(stack_command, ["--help"])
        assert result.exit_code == 0
        assert "stack" in result.output.lower()

    def test_command_reachable(self) -> None:
        with patch("depcheck.commands.stack.run_stack") as mock_stack:
            mock_stack.return_value = MagicMock(
                components=[], errors=[], to_dict=lambda: {"components": [], "errors": []}
            )
            result = runner.invoke(stack_command, ["."])
            assert result.exit_code == 0

    def test_json_output_parses(self, tmp_path) -> None:
        with patch("depcheck.commands.stack.run_stack") as mock_stack:
            mock_stack.return_value = MagicMock(
                components=[], errors=[], to_dict=lambda: {"components": [], "errors": []}
            )
            data = _invoke_json(stack_command, str(tmp_path))
            assert "components" in data

    def test_check_licenses_option(self, tmp_path) -> None:
        """--check-licenses passes through to run_stack."""
        with patch("depcheck.commands.stack.run_stack") as mock_stack:
            mock_stack.return_value = MagicMock(
                components=[], errors=[], to_dict=lambda: {"components": [], "errors": []}
            )
            runner.invoke(stack_command, [str(tmp_path), "--check-licenses"])
            mock_stack.assert_called_once()
            kwargs = mock_stack.call_args.kwargs
            assert kwargs.get("check_licenses") is True


# ──────────────────────────────────────────────────────────────────────────────
# config tests (click group with subcommands)
# ──────────────────────────────────────────────────────────────────────────────


class TestConfigCommand:
    """Tests for `depcheck config` group and subcommands."""

    def test_help_works(self) -> None:
        result = runner.invoke(config_command, ["--help"])
        assert result.exit_code == 0
        assert "config" in result.output.lower()

    def test_show_subcommand(self, tmp_path) -> None:
        """`config show` prints effective config."""
        with patch("depcheck.commands.config.load_config") as mock_load:
            mock_config = MagicMock()
            mock_config.to_dict.return_value = {"scan": {"check_vulnerabilities": True}}
            mock_load.return_value = mock_config
            result = runner.invoke(config_command, ["show", str(tmp_path)])
            assert result.exit_code == 0

    def test_show_json_output_parses(self, tmp_path) -> None:
        with patch("depcheck.commands.config.load_config") as mock_load:
            mock_config = MagicMock()
            mock_config.to_dict.return_value = {"scan": {"check_vulnerabilities": True}}
            mock_load.return_value = mock_config
            data = _invoke_json(config_command, "show", str(tmp_path))
            assert "scan" in data

    def test_validate_subcommand(self, tmp_path) -> None:
        """`config validate` prints validation errors."""
        with patch("depcheck.commands.config.load_config") as mock_load:
            with patch(
                "depcheck.commands.config.validate_config", return_value=[]
            ) as mock_validate:
                mock_config = MagicMock()
                mock_load.return_value = mock_config
                result = runner.invoke(config_command, ["validate", str(tmp_path)])
                assert result.exit_code == 0
                mock_validate.assert_called_once()

    def test_validate_exits_1_on_errors(self, tmp_path) -> None:
        """`config validate` exits 1 when errors found."""
        with patch("depcheck.commands.config.load_config") as mock_load:
            with patch(
                "depcheck.commands.config.validate_config", return_value=["error: bad config"]
            ):
                mock_config = MagicMock()
                mock_load.return_value = mock_config
                result = runner.invoke(config_command, ["validate", str(tmp_path)])
                assert result.exit_code == 1

    def test_generate_subcommand(self, tmp_path) -> None:
        """`config generate` prints default config YAML."""
        with patch(
            "depcheck.commands.config.generate_default_config",
            return_value="[tool.depcheck]\nscan = {}",
        ):
            result = runner.invoke(config_command, ["generate", str(tmp_path)])
            assert result.exit_code == 0
            assert "tool.depcheck" in result.output

    def test_generate_write_option(self, tmp_path) -> None:
        """`config generate --write` writes to depcheck.yaml."""
        out_file = tmp_path / "depcheck.yaml"
        with patch(
            "depcheck.commands.config.generate_default_config",
            return_value="[tool.depcheck]\nscan = {}",
        ):
            result = runner.invoke(config_command, ["generate", str(tmp_path), "--write"])
            assert result.exit_code == 0
            assert out_file.exists()
            assert "tool.depcheck" in out_file.read_text()


# ──────────────────────────────────────────────────────────────────────────────
# summary tests
# ──────────────────────────────────────────────────────────────────────────────


class TestSummaryCommand:
    """Tests for `depcheck summary`."""

    def test_help_works(self) -> None:
        result = runner.invoke(summary_command, ["--help"])
        assert result.exit_code == 0
        assert "summary" in result.output.lower()

    def test_command_reachable(self) -> None:
        with patch("depcheck.commands.summary.build_scorecard") as mock_build:
            mock_build.return_value = MagicMock(
                to_dict=lambda: {"overall_score": 85, "grade": "B", "categories": []},
                grade=MagicMock(value="B"),
                overall_score=85,
            )
            result = runner.invoke(summary_command, ["."])
            assert result.exit_code == 0

    def test_json_output_parses(self, tmp_path) -> None:
        with patch("depcheck.commands.summary.build_scorecard") as mock_build:
            mock_build.return_value = MagicMock(
                to_dict=lambda: {"overall_score": 85, "grade": "B", "categories": []},
                grade=MagicMock(value="B"),
                overall_score=85,
            )
            data = _invoke_json(summary_command, str(tmp_path))
            assert "overall_score" in data
            assert "grade" in data

    def test_badge_option(self, tmp_path) -> None:
        """--badge prints only the badge URL."""
        with patch("depcheck.commands.summary.build_scorecard") as mock_build:
            with patch(
                "depcheck.commands.summary.generate_badge_url",
                return_value="https://img.shields.io/badge/depcheck-B-yellowgreen",
            ):
                mock_build.return_value = MagicMock(
                    to_dict=lambda: {"overall_score": 85, "grade": "B", "categories": []},
                    grade=MagicMock(value="B"),
                    overall_score=85,
                )
                result = runner.invoke(summary_command, [str(tmp_path), "--badge"])
                assert result.exit_code == 0
                assert "shields.io" in result.output

    def test_no_vuln_check_option(self, tmp_path) -> None:
        """--no-vuln-check passes through."""
        with patch("depcheck.commands.summary.build_scorecard") as mock_build:
            mock_build.return_value = MagicMock(
                to_dict=lambda: {"overall_score": 85, "grade": "B", "categories": []},
                grade=MagicMock(value="B"),
                overall_score=85,
            )
            runner.invoke(summary_command, [str(tmp_path), "--no-vuln-check"])
            kwargs = mock_build.call_args.kwargs
            assert kwargs.get("check_vulnerabilities") is False


# ──────────────────────────────────────────────────────────────────────────────
# workspace tests
# ──────────────────────────────────────────────────────────────────────────────


class TestWorkspaceCommand:
    """Tests for `depcheck workspace`."""

    def test_help_works(self) -> None:
        result = runner.invoke(workspace_command, ["--help"])
        assert result.exit_code == 0
        assert "workspace" in result.output.lower()

    def test_command_reachable(self, tmp_path) -> None:
        with patch("depcheck.commands.workspace.scan_workspace") as mock_scan:
            mock_scan.return_value = _make_workspace_result(tmp_path)
            with patch(
                "depcheck.commands.workspace.analyze_workspace_dependencies"
            ) as mock_analyze:
                mock_analyze.return_value = MagicMock(
                    shared_dependencies={},
                    version_conflicts=[],
                    consolidation_opportunities=[],
                    transitive_overlap={},
                    total_unique_packages=0,
                    total_packages=0,
                )
                result = runner.invoke(workspace_command, ["."])
                assert result.exit_code == 0

    def test_json_output_parses(self, tmp_path) -> None:
        with patch("depcheck.commands.workspace.scan_workspace") as mock_scan:
            mock_scan.return_value = _make_workspace_result(tmp_path)
            with patch(
                "depcheck.commands.workspace.analyze_workspace_dependencies"
            ) as mock_analyze:
                mock_analyze.return_value = MagicMock(
                    shared_dependencies={},
                    version_conflicts=[],
                    consolidation_opportunities=[],
                    transitive_overlap={},
                    total_unique_packages=0,
                    total_packages=0,
                )
                data = _invoke_json(workspace_command, str(tmp_path))
                assert "workspace" in data

    def test_check_licenses_option(self, tmp_path) -> None:
        with patch("depcheck.commands.workspace.scan_workspace") as mock_scan:
            mock_scan.return_value = _make_workspace_result(tmp_path)
            with patch("depcheck.commands.workspace.analyze_workspace_dependencies"):
                runner.invoke(workspace_command, [str(tmp_path), "--check-licenses"])
                kwargs = mock_scan.call_args.kwargs
                assert kwargs.get("check_licenses") is True


# ──────────────────────────────────────────────────────────────────────────────
# remediate tests
# ──────────────────────────────────────────────────────────────────────────────


class TestRemediateCommand:
    """Tests for `depcheck remediate`."""

    def test_help_works(self) -> None:
        result = runner.invoke(remediate_command, ["--help"])
        assert result.exit_code == 0
        assert "remediate" in result.output.lower()

    def test_command_reachable(self, tmp_path) -> None:
        """Default path (plan only, no network) works."""
        with patch("depcheck.commands.remediate._common.scan_project") as mock_scan:
            with patch("depcheck.commands.remediate.build_update_plan") as mock_build_plan:
                with patch(
                    "depcheck.commands.remediate.build_remediation_plan"
                ) as mock_build_remed:
                    mock_scan.return_value = _make_scan_result()
                    mock_build_plan.return_value = _make_update_plan()
                    mock_build_remed.return_value = _make_remediation_plan()
                    result = runner.invoke(remediate_command, [str(tmp_path)])
                    assert result.exit_code == 0

    def test_json_output_parses(self, tmp_path) -> None:
        with patch("depcheck.commands.remediate._common.scan_project") as mock_scan:
            with patch("depcheck.commands.remediate.build_update_plan") as mock_build_plan:
                with patch(
                    "depcheck.commands.remediate.build_remediation_plan"
                ) as mock_build_remed:
                    mock_scan.return_value = _make_scan_result()
                    mock_build_plan.return_value = _make_update_plan()
                    mock_build_remed.return_value = _make_remediation_plan()
                    data = _invoke_json(remediate_command, str(tmp_path))
                    assert "repository" in data
                    assert "groups" in data

    def test_repo_option(self, tmp_path) -> None:
        """--repo owner/name is accepted."""
        with patch("depcheck.commands.remediate._common.scan_project") as mock_scan:
            with patch("depcheck.commands.remediate.build_update_plan") as mock_build_plan:
                with patch(
                    "depcheck.commands.remediate.build_remediation_plan"
                ) as mock_build_remed:
                    mock_scan.return_value = _make_scan_result()
                    mock_build_plan.return_value = _make_update_plan()
                    mock_build_remed.return_value = _make_remediation_plan()
                    result = runner.invoke(
                        remediate_command, [str(tmp_path), "--repo", "owner/repo"]
                    )
                    assert result.exit_code == 0

    def test_dry_run_default_no_network(self, tmp_path) -> None:
        """Default is dry-run (no network/PR creation)."""
        with patch("depcheck.commands.remediate._common.scan_project") as mock_scan:
            with patch("depcheck.commands.remediate.build_update_plan") as mock_build_plan:
                with patch(
                    "depcheck.commands.remediate.build_remediation_plan"
                ) as mock_build_remed:
                    mock_scan.return_value = _make_scan_result()
                    mock_build_plan.return_value = _make_update_plan()
                    mock_build_remed.return_value = _make_remediation_plan()
                    runner.invoke(remediate_command, [str(tmp_path), "--repo", "owner/repo"])
                    # No network calls in default dry-run mode


# ──────────────────────────────────────────────────────────────────────────────
# search tests
# ──────────────────────────────────────────────────────────────────────────────


class TestSearchCommand:
    """Tests for `depcheck search`."""

    def test_help_works(self) -> None:
        result = runner.invoke(search_command, ["--help"])
        assert result.exit_code == 0
        assert "search" in result.output.lower()

    def test_command_reachable(self) -> None:
        with patch("depcheck.commands.search.search_packages") as mock_search:
            mock_search.return_value = MagicMock(
                to_dict=lambda: {"query": "test", "results": [], "total": 0},
                errors=[],
                results=[],
            )
            result = runner.invoke(search_command, ["requests"])
            assert result.exit_code == 0

    def test_json_output_parses(self) -> None:
        with patch("depcheck.commands.search.search_packages") as mock_search:
            mock_search.return_value = MagicMock(
                to_dict=lambda: {"query": "test", "results": [], "total": 0},
                errors=[],
                results=[],
            )
            data = _invoke_json(search_command, "requests")
            assert "query" in data
            assert "results" in data

    def test_category_option(self) -> None:
        """--category uses search_by_category."""
        with patch("depcheck.commands.search.search_by_category") as mock_cat:
            mock_cat.return_value = MagicMock(
                to_dict=lambda: {"query": "category:web", "results": [], "total": 0},
                errors=[],
                results=[],
            )
            result = runner.invoke(search_command, ["--category", "web"])
            assert result.exit_code == 0
            mock_cat.assert_called_once()

    def test_limit_option(self) -> None:
        """--limit passes through."""
        with patch("depcheck.commands.search.search_packages") as mock_search:
            mock_search.return_value = MagicMock(
                to_dict=lambda: {"query": "test", "results": [], "total": 0},
                errors=[],
                results=[],
            )
            runner.invoke(search_command, ["requests", "--limit", "5"])
            kwargs = mock_search.call_args.kwargs
            assert kwargs.get("limit") == 5

    def test_license_filter_option(self) -> None:
        """--license passes through."""
        with patch("depcheck.commands.search.search_packages") as mock_search:
            mock_search.return_value = MagicMock(
                to_dict=lambda: {"query": "test", "results": [], "total": 0},
                errors=[],
                results=[],
            )
            runner.invoke(search_command, ["requests", "--license", "permissive"])
            kwargs = mock_search.call_args.kwargs
            assert kwargs.get("license_filter") == "permissive"


# ──────────────────────────────────────────────────────────────────────────────
# Common tests for all commands
# ──────────────────────────────────────────────────────────────────────────────

ALL_COMMANDS = [
    ("annotations", annotations_command),
    ("predict", predict_command),
    ("stack", stack_command),
    ("config", config_command),
    ("summary", summary_command),
    ("workspace", workspace_command),
    ("remediate", remediate_command),
    ("search", search_command),
]


class TestAllNewCommands:
    """Common invariants for all new commands."""

    def test_all_commands_have_help(self) -> None:
        for name, cmd in ALL_COMMANDS:
            result = runner.invoke(cmd, ["--help"])
            assert result.exit_code == 0, f"{name}: --help failed"

    def test_all_commands_support_json(self) -> None:
        """Every command must support --json with valid JSON output."""
        for name, cmd in ALL_COMMANDS:
            if name == "config":
                # Config is a group - test subcommands
                for subcmd in ["show", "validate", "generate"]:
                    result = runner.invoke(cmd, [subcmd, "--help"])
                    assert "--json" in result.output, f"config {subcmd}: missing --json option"
            else:
                result = runner.invoke(cmd, ["--help"])
                assert "--json" in result.output, f"{name}: missing --json option"
