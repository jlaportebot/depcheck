"""Tests for the doctor module — project best practices checker."""

from __future__ import annotations

import tempfile
from pathlib import Path

from depcheck.doctor import (
    DoctorCheck,
    DoctorResult,
    check_ci_workflows,
    check_contributing,
    check_dependabot_config,
    check_gitignore,
    check_license_file,
    check_pre_commit_config,
    check_pyproject_toml,
    check_pytest_config,
    check_readme,
    check_security_files,
    render_doctor_result,
    run_doctor_checks,
)


class TestDoctorCheck:
    """Tests for DoctorCheck dataclass."""

    def test_defaults(self) -> None:
        check = DoctorCheck(name="test", passed=True, message="ok")
        assert check.name == "test"
        assert check.passed is True
        assert check.message == "ok"
        assert check.severity == "info"
        assert check.fix_hint is None

    def test_custom_values(self) -> None:
        check = DoctorCheck(
            name="test",
            passed=False,
            message="failed",
            severity="error",
            fix_hint="fix it",
        )
        assert check.severity == "error"
        assert check.fix_hint == "fix it"


class TestDoctorResult:
    """Tests for DoctorResult dataclass."""

    def test_empty_result(self) -> None:
        result = DoctorResult(project_path=Path("/tmp"))
        assert result.passed_count == 0
        assert result.failed_count == 0
        assert result.error_count == 0
        assert result.warning_count == 0
        assert result.overall_status == "pass"

    def test_passed_count(self) -> None:
        result = DoctorResult(
            project_path=Path("/tmp"),
            checks=[
                DoctorCheck(name="a", passed=True, message="ok"),
                DoctorCheck(name="b", passed=True, message="ok"),
                DoctorCheck(name="c", passed=False, message="fail"),
            ],
        )
        assert result.passed_count == 2
        assert result.failed_count == 1

    def test_error_warning_counts(self) -> None:
        result = DoctorResult(
            project_path=Path("/tmp"),
            checks=[
                DoctorCheck(name="a", passed=True, message="ok"),
                DoctorCheck(name="b", passed=False, message="err", severity="error"),
                DoctorCheck(name="c", passed=False, message="warn", severity="warning"),
                DoctorCheck(name="d", passed=False, message="info", severity="info"),
            ],
        )
        assert result.error_count == 1
        assert result.warning_count == 1

    def test_overall_status_error(self) -> None:
        result = DoctorResult(
            project_path=Path("/tmp"),
            checks=[DoctorCheck(name="a", passed=False, message="err", severity="error")],
        )
        assert result.overall_status == "error"

    def test_overall_status_warning(self) -> None:
        result = DoctorResult(
            project_path=Path("/tmp"),
            checks=[DoctorCheck(name="a", passed=False, message="warn", severity="warning")],
        )
        assert result.overall_status == "warning"

    def test_overall_status_pass(self) -> None:
        result = DoctorResult(
            project_path=Path("/tmp"),
            checks=[DoctorCheck(name="a", passed=True, message="ok")],
        )
        assert result.overall_status == "pass"


class TestCheckCiWorkflows:
    """Tests for check_ci_workflows."""

    def test_no_workflows_dir(self, tmp_path: Path) -> None:
        check = check_ci_workflows(tmp_path)
        assert not check.passed
        assert check.severity == "warning"
        assert "workflows" in check.message.lower()

    def test_empty_workflows_dir(self, tmp_path: Path) -> None:
        (tmp_path / ".github" / "workflows").mkdir(parents=True)
        check = check_ci_workflows(tmp_path)
        assert not check.passed
        assert check.severity == "warning"

    def test_has_workflow_files(self, tmp_path: Path) -> None:
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI\n")
        check = check_ci_workflows(tmp_path)
        assert check.passed
        assert "1 workflow" in check.message

    def test_multiple_workflow_files(self, tmp_path: Path) -> None:
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI\n")
        (workflows_dir / "release.yml").write_text("name: Release\n")
        check = check_ci_workflows(tmp_path)
        assert check.passed
        assert "2 workflow" in check.message


class TestCheckPreCommitConfig:
    """Tests for check_pre_commit_config."""

    def test_no_config(self, tmp_path: Path) -> None:
        check = check_pre_commit_config(tmp_path)
        assert not check.passed
        assert check.severity == "info"

    def test_has_pre_commit(self, tmp_path: Path) -> None:
        (tmp_path / ".pre-commit-config.yaml").write_text("repos: []\n")
        check = check_pre_commit_config(tmp_path)
        assert check.passed
        assert "pre-commit" in check.message

    def test_has_prek(self, tmp_path: Path) -> None:
        (tmp_path / ".prek.toml").write_text("[hooks]\n")
        check = check_pre_commit_config(tmp_path)
        assert check.passed
        assert "prek" in check.message


class TestCheckDependabotConfig:
    """Tests for check_dependabot_config."""

    def test_no_config(self, tmp_path: Path) -> None:
        check = check_dependabot_config(tmp_path)
        assert not check.passed
        assert check.severity == "info"

    def test_has_config(self, tmp_path: Path) -> None:
        github_dir = tmp_path / ".github"
        github_dir.mkdir(parents=True)
        (github_dir / "dependabot.yml").write_text("version: 2\n")
        check = check_dependabot_config(tmp_path)
        assert check.passed


class TestCheckSecurityFiles:
    """Tests for check_security_files."""

    def test_no_files(self, tmp_path: Path) -> None:
        check = check_security_files(tmp_path)
        assert not check.passed

    def test_only_security_md(self, tmp_path: Path) -> None:
        (tmp_path / "SECURITY.md").write_text("# Security\n")
        check = check_security_files(tmp_path)
        assert not check.passed
        assert "CODE_OF_CONDUCT.md" in check.message

    def test_only_code_of_conduct(self, tmp_path: Path) -> None:
        (tmp_path / "CODE_OF_CONDUCT.md").write_text("# Code of Conduct\n")
        check = check_security_files(tmp_path)
        assert not check.passed
        assert "SECURITY.md" in check.message

    def test_both_files(self, tmp_path: Path) -> None:
        (tmp_path / "SECURITY.md").write_text("# Security\n")
        (tmp_path / "CODE_OF_CONDUCT.md").write_text("# Code of Conduct\n")
        check = check_security_files(tmp_path)
        assert check.passed


class TestCheckLicenseFile:
    """Tests for check_license_file."""

    def test_no_license(self, tmp_path: Path) -> None:
        check = check_license_file(tmp_path)
        assert not check.passed
        assert check.severity == "warning"

    def test_has_license(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE").write_text("MIT License\n")
        check = check_license_file(tmp_path)
        assert check.passed
        assert "LICENSE" in check.message

    def test_has_license_md(self, tmp_path: Path) -> None:
        (tmp_path / "LICENSE.md").write_text("MIT License\n")
        check = check_license_file(tmp_path)
        assert check.passed
        assert "LICENSE.md" in check.message


class TestCheckReadme:
    """Tests for check_readme."""

    def test_no_readme(self, tmp_path: Path) -> None:
        check = check_readme(tmp_path)
        assert not check.passed
        assert check.severity == "warning"

    def test_has_readme(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("# Project\n")
        check = check_readme(tmp_path)
        assert check.passed

    def test_has_readme_rst(self, tmp_path: Path) -> None:
        (tmp_path / "README.rst").write_text("Project\n=======\n")
        check = check_readme(tmp_path)
        assert check.passed


class TestCheckContributing:
    """Tests for check_contributing."""

    def test_no_contributing(self, tmp_path: Path) -> None:
        check = check_contributing(tmp_path)
        assert not check.passed
        assert check.severity == "info"

    def test_has_contributing(self, tmp_path: Path) -> None:
        (tmp_path / "CONTRIBUTING.md").write_text("# Contributing\n")
        check = check_contributing(tmp_path)
        assert check.passed


class TestCheckPyprojectToml:
    """Tests for check_pyproject_toml."""

    def test_no_pyproject(self, tmp_path: Path) -> None:
        check = check_pyproject_toml(tmp_path)
        assert not check.passed
        assert check.severity == "error"

    def test_minimal_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "test"\nversion = "0.1.0"\n'
            'description = "test"\nrequires-python = ">=3.11"\n'
        )
        check = check_pyproject_toml(tmp_path)
        assert check.passed

    def test_pyproject_missing_fields(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text('[project]\nname = "test"\n')
        check = check_pyproject_toml(tmp_path)
        assert not check.passed
        assert check.severity == "warning"
        assert "version" in check.message or "description" in check.message

    def test_invalid_toml(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text("[project\ninvalid toml ===")
        check = check_pyproject_toml(tmp_path)
        assert not check.passed
        assert check.severity == "error"


class TestCheckGitignore:
    """Tests for check_gitignore."""

    def test_no_gitignore(self, tmp_path: Path) -> None:
        check = check_gitignore(tmp_path)
        assert not check.passed
        assert check.severity == "warning"

    def test_has_gitignore(self, tmp_path: Path) -> None:
        (tmp_path / ".gitignore").write_text("__pycache__/\n*.pyc\n")
        check = check_gitignore(tmp_path)
        assert check.passed


class TestCheckPytestConfig:
    """Tests for check_pytest_config."""

    def test_no_config_no_tests_dir(self, tmp_path: Path) -> None:
        check = check_pytest_config(tmp_path)
        assert not check.passed

    def test_has_tests_dir(self, tmp_path: Path) -> None:
        (tmp_path / "tests").mkdir()
        check = check_pytest_config(tmp_path)
        assert check.passed

    def test_has_pytest_in_pyproject(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "test"\n\n[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
        )
        check = check_pytest_config(tmp_path)
        assert check.passed


class TestRunDoctorChecks:
    """Tests for run_doctor_checks integration."""

    def test_runs_all_checks(self, tmp_path: Path) -> None:
        result = run_doctor_checks(tmp_path)
        assert len(result.checks) == 10
        assert result.project_path == tmp_path.resolve()

    def test_minimal_project(self, tmp_path: Path) -> None:
        result = run_doctor_checks(tmp_path)
        assert result.failed_count > 0

    def test_well_configured_project(self, tmp_path: Path) -> None:
        # Create a well-configured Python project
        (tmp_path / "README.md").write_text("# Project\n")
        (tmp_path / "LICENSE").write_text("MIT License\n")
        (tmp_path / ".gitignore").write_text("__pycache__/\n")
        (tmp_path / "SECURITY.md").write_text("# Security\n")
        (tmp_path / "CODE_OF_CONDUCT.md").write_text("# Code of Conduct\n")
        (tmp_path / "CONTRIBUTING.md").write_text("# Contributing\n")
        (tmp_path / "pyproject.toml").write_text(
            '[project]\nname = "test"\nversion = "0.1.0"\n'
            'description = "test project"\nrequires-python = ">=3.11"\n'
        )
        workflows_dir = tmp_path / ".github" / "workflows"
        workflows_dir.mkdir(parents=True)
        (workflows_dir / "ci.yml").write_text("name: CI\n")
        (tmp_path / ".github" / "dependabot.yml").write_text("version: 2\n")
        (tmp_path / ".prek.toml").write_text("[hooks]\n")
        (tmp_path / "tests").mkdir()

        result = run_doctor_checks(tmp_path)
        assert result.passed_count == 10
        assert result.overall_status == "pass"


class TestRenderDoctorResult:
    """Tests for render_doctor_result."""

    def test_text_output(self) -> None:
        result = DoctorResult(
            project_path=Path("/tmp/test"),
            checks=[
                DoctorCheck(name="CI", passed=True, message="Found 1 workflow"),
                DoctorCheck(name="License", passed=False, message="No LICENSE", severity="warning"),
            ],
        )
        output = render_doctor_result(result)
        assert "Project:" in output
        assert "✓ CI" in output
        assert "✗ License" in output
        assert "WARN" in output

    def test_json_output(self) -> None:
        import json

        result = DoctorResult(
            project_path=Path("/tmp/test"),
            checks=[
                DoctorCheck(name="CI", passed=True, message="ok"),
            ],
        )
        output = render_doctor_result(result, json_output=True)
        data = json.loads(output)
        assert data["overall_status"] == "pass"
        assert len(data["checks"]) == 1
        assert data["summary"]["passed"] == 1

    def test_json_output_with_fix_hint(self) -> None:
        import json

        result = DoctorResult(
            project_path=Path("/tmp/test"),
            checks=[
                DoctorCheck(
                    name="License",
                    passed=False,
                    message="No LICENSE",
                    severity="warning",
                    fix_hint="Add a LICENSE file",
                ),
            ],
        )
        output = render_doctor_result(result, json_output=True)
        data = json.loads(output)
        assert data["checks"][0]["fix_hint"] == "Add a LICENSE file"


class TestDoctorCLICommand:
    """Integration tests for the doctor CLI command."""

    def test_doctor_help(self) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["doctor", "--help"])
        assert result.exit_code == 0
        assert "best practices" in result.output.lower() or "doctor" in result.output.lower()

    def test_doctor_on_current_project(self) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["doctor", "."])
        # Should not crash even on a partial project
        assert result.exit_code in (0, 1)

    def test_doctor_json_output(self) -> None:
        from click.testing import CliRunner

        from depcheck.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["doctor", ".", "--json"])
        assert result.exit_code in (0, 1)
        import json

        data = json.loads(result.output)
        assert "checks" in data
        assert "overall_status" in data
