"""Tests for depcheck.config environment overrides and explicit config loading."""

from __future__ import annotations

from pathlib import Path

import pytest

from depcheck.config import Config, apply_env_overrides, load_config


def test_apply_env_overrides_bool_values(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPCHECK_QUIET", "true")
    monkeypatch.setenv("DEPCHECK_OUTPUT_JSON", "false")
    monkeypatch.delenv("DEPCHECK_FAIL_ON", raising=False)

    config = Config()
    apply_env_overrides(config)

    assert config.scan.quiet is True
    assert config.scan.output_json is False


def test_apply_env_overrides_string_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPCHECK_FAIL_ON", "vulnerable")

    config = Config()
    apply_env_overrides(config)

    assert config.scan.fail_on == "vulnerable"


def test_apply_env_overrides_unknown_env_ignored(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEPCHECK_NOT_A_REAL_KEY", "whatever")

    config = Config()
    apply_env_overrides(config)  # should not raise

    assert config.scan.fail_on is None


def test_load_config_reads_default_pyproject(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        '[tool.depcheck.scan]\nfail_on = "error"\ncheck_vulnerabilities = false\n'
    )

    config = load_config(project_path=tmp_path)

    assert config.scan.fail_on == "error"
    assert config.scan.check_vulnerabilities is False


def test_load_config_uses_explicit_config_path(tmp_path: Path) -> None:
    project_pyproject = tmp_path / "pyproject.toml"
    project_pyproject.write_text('[tool.depcheck.scan]\nfail_on = "critical"\n')

    explicit = tmp_path / "other.toml"
    explicit.write_text('[tool.depcheck.scan]\nfail_on = "warning"\n')

    config = load_config(project_path=tmp_path, config_path=explicit)

    # The explicit file wins over the project's pyproject.toml.
    assert config.scan.fail_on == "warning"


def test_load_config_missing_file_uses_defaults(tmp_path: Path) -> None:
    config = load_config(project_path=tmp_path)

    assert config.scan.fail_on is None
    assert config.scan.check_vulnerabilities is True
