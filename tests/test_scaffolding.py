"""Tests for depcheck scaffolding module."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from depcheck.scaffolding import render_scaffold_markdown, scaffold_project


class TestScaffoldProject:
    """Tests for scaffold_project function."""

    def test_scaffold_creates_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scaffold_project(tmpdir, workflow=False, force=False)
            assert result.config_path == str(Path(tmpdir) / "depcheck.yaml")
            assert result.config_created is True
            assert result.workflow_path is None
            assert result.workflow_created is False
            assert result.skipped == []
            assert result.warnings == []

    def test_scaffold_creates_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scaffold_project(tmpdir, workflow=True, force=False)
            assert result.config_path == str(Path(tmpdir) / "depcheck.yaml")
            assert result.config_created is True
            assert result.workflow_path == str(
                Path(tmpdir) / ".github" / "workflows" / "depcheck.yml"
            )
            assert result.workflow_created is True

    def test_scaffold_skips_existing_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "depcheck.yaml"
            config_path.write_text("# existing config\n")
            result = scaffold_project(tmpdir, workflow=False, force=False)
            assert result.config_created is False
            assert "depcheck.yaml" in result.skipped

    def test_scaffold_skips_existing_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            workflow_dir = Path(tmpdir) / ".github" / "workflows"
            workflow_dir.mkdir(parents=True)
            workflow_path = workflow_dir / "depcheck.yml"
            workflow_path.write_text("# existing workflow\n")
            result = scaffold_project(tmpdir, workflow=True, force=False)
            assert result.workflow_created is False
            assert str(workflow_path) in result.skipped or "depcheck.yml" in " ".join(
                result.skipped
            )

    def test_scaffold_force_overwrites(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "depcheck.yaml"
            config_path.write_text("# old config\n")
            result = scaffold_project(tmpdir, workflow=False, force=True)
            assert result.config_created is True
            assert "depcheck.yaml" not in result.skipped

    def test_scaffold_config_has_correct_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            scaffold_project(tmpdir, workflow=False, force=False)
            config_path = Path(tmpdir) / "depcheck.yaml"
            content = config_path.read_text()
            # Check for key sections from config.py
            assert "scan:" in content
            assert "check_vulnerabilities:" in content
            assert "check_licenses:" in content
            assert "allowed_license_categories:" in content
            assert "denied_licenses:" in content
            assert "fail_on:" in content
            assert "budget:" in content
            assert "policy:" in content
            # Check budget keys
            assert "total:" in content
            assert "direct:" in content
            assert "transitive:" in content
            assert "dev:" in content
            assert "optional:" in content

    def test_scaffold_workflow_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            scaffold_project(tmpdir, workflow=True, force=False)
            workflow_path = Path(tmpdir) / ".github" / "workflows" / "depcheck.yml"
            content = workflow_path.read_text()
            assert "name:" in content
            assert "on:" in content
            assert "push:" in content or "pull_request:" in content
            assert "jobs:" in content
            assert "depcheck-scan:" in content or "scan:" in content
            assert "depcheck-cli" in content
            assert "depcheck scan --fail-on vulnerable --json" in content

    def test_scaffold_does_not_write_outside_project_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a subdirectory as project
            project_dir = Path(tmpdir) / "myproject"
            project_dir.mkdir()
            result = scaffold_project(str(project_dir), workflow=True, force=False)
            # Config should be in project_dir
            assert str(Path(project_dir) / "depcheck.yaml") == result.config_path
            # Workflow should be in project_dir/.github/workflows
            assert (
                str(Path(project_dir) / ".github" / "workflows" / "depcheck.yml")
                == result.workflow_path
            )

    def test_scaffold_result_to_dict(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scaffold_project(tmpdir, workflow=True, force=False)
            d = result.to_dict()
            assert d["config_path"] == str(Path(tmpdir) / "depcheck.yaml")
            assert d["config_created"] is True
            assert d["workflow_path"] == str(
                Path(tmpdir) / ".github" / "workflows" / "depcheck.yml"
            )
            assert d["workflow_created"] is True
            assert "skipped" in d
            assert "warnings" in d


class TestRenderScaffoldMarkdown:
    """Tests for render_scaffold_markdown function."""

    def test_render_basic(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            result = scaffold_project(tmpdir, workflow=True, force=False)
            md = render_scaffold_markdown(result)
            assert isinstance(md, str)
            assert "# depcheck Scaffold Summary" in md
            assert "depcheck.yaml" in md
            assert ".github/workflows/depcheck.yml" in md
            assert "Created" in md

    def test_render_shows_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "depcheck.yaml"
            config_path.write_text("# existing\n")
            result = scaffold_project(tmpdir, workflow=True, force=False)
            md = render_scaffold_markdown(result)
            assert "Skipped" in md or "skipped" in md.lower()
            assert "depcheck.yaml" in md


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
