"""Tests for the config module."""

from __future__ import annotations

import tempfile
from pathlib import Path

from depcheck.config import (
    BudgetConfig,
    Config,
    PolicyConfig,
    ScanConfig,
    generate_default_config,
    load_config,
    validate_config,
)


class TestScanConfig:
    """Tests for ScanConfig."""

    def test_defaults(self) -> None:
        config = ScanConfig()
        assert config.check_vulnerabilities is True
        assert config.check_licenses is False
        assert config.allowed_license_categories == []
        assert config.denied_licenses == []
        assert config.fail_on is None
        assert config.quiet is False
        assert config.output_json is False

    def test_custom_values(self) -> None:
        config = ScanConfig(
            check_vulnerabilities=False,
            check_licenses=True,
            allowed_license_categories=["permissive"],
            denied_licenses=["GPL-3.0"],
            fail_on="vulnerable",
            quiet=True,
            output_json=True,
        )
        assert config.check_vulnerabilities is False
        assert config.check_licenses is True
        assert config.allowed_license_categories == ["permissive"]
        assert config.denied_licenses == ["GPL-3.0"]
        assert config.fail_on == "vulnerable"
        assert config.quiet is True
        assert config.output_json is True


class TestConfig:
    """Tests for Config."""

    def test_default_config(self) -> None:
        config = Config()
        assert isinstance(config.scan, ScanConfig)
        assert isinstance(config.budget, BudgetConfig)
        assert isinstance(config.policy, PolicyConfig)
        assert config.project_path == Path.cwd()

    def test_load_from_nonexistent_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = load_config(Path(tmpdir) / "nonexistent")
            assert isinstance(config, Config)
            assert config.project_path == Path(tmpdir) / "nonexistent"

    def test_load_from_pyproject_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject = Path(tmpdir) / "pyproject.toml"
            pyproject.write_text(
                """
[tool.depcheck.scan]
check_vulnerabilities = false
check_licenses = true
allowed_license_categories = ["permissive", "copyleft"]
denied_licenses = ["GPL-3.0"]
fail_on = "vulnerable"
quiet = true
output_json = false

[tool.depcheck.budget]
total = 100
direct = 20

[tool.depcheck.policy.license]
deny_copyleft = true
severity = "error"
""",
                encoding="utf-8",
            )

            config = load_config(tmpdir)
            assert config.scan.check_vulnerabilities is False
            assert config.scan.check_licenses is True
            assert config.scan.allowed_license_categories == ["permissive", "copyleft"]
            assert config.scan.denied_licenses == ["GPL-3.0"]
            assert config.scan.fail_on == "vulnerable"
            assert config.scan.quiet is True
            assert config.scan.output_json is False
            assert config.budget.total == 100
            assert config.budget.direct == 20
            assert len(config.policy.rules) == 1
            assert config.policy.rules[0].name == "license-policy"
            assert config.policy.rules[0].deny_copyleft is True

    def test_cli_overrides(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject = Path(tmpdir) / "pyproject.toml"
            pyproject.write_text(
                """
[tool.depcheck.scan]
check_vulnerabilities = true
fail_on = "outdated"
""",
                encoding="utf-8",
            )

            config = load_config(
                tmpdir,
                cli_overrides={"scan": {"fail_on": "vulnerable", "quiet": True}},
            )
            assert config.scan.fail_on == "vulnerable"  # Overridden
            assert config.scan.quiet is True  # New override
            assert config.scan.check_vulnerabilities is True  # From pyproject.toml

    def test_to_dict(self) -> None:
        config = Config()
        d = config.to_dict()
        assert "scan" in d
        assert "budget" in d
        assert "policy" in d
        assert "project_path" in d
        assert d["scan"]["check_vulnerabilities"] is True


class TestValidateConfig:
    """Tests for validate_config."""

    def test_valid_config(self) -> None:
        config = Config()
        issues = validate_config(config)
        assert issues == []

    def test_invalid_fail_on(self) -> None:
        config = Config()
        config.scan.fail_on = "invalid"
        issues = validate_config(config)
        assert any("invalid value 'invalid'" in issue for issue in issues)

    def test_negative_budget(self) -> None:
        config = Config()
        config.budget.total = -1
        issues = validate_config(config)
        assert any("must be non-negative" in issue for issue in issues)


class TestGenerateDefaultConfig:
    """Tests for generate_default_config."""

    def test_generates_valid_toml(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            content = generate_default_config(tmpdir)
            assert "[tool.depcheck]" in content
            assert "[tool.depcheck.scan]" in content
            assert "[tool.depcheck.budget]" in content
            assert "[tool.depcheck.policy]" in content
            assert "check_vulnerabilities = true" in content
            assert "max_packages = 50" in content

    def test_includes_existing_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            pyproject = Path(tmpdir) / "pyproject.toml"
            pyproject.write_text(
                """
[tool.depcheck.scan]
check_vulnerabilities = false

[tool.depcheck.budget]
max_packages = 200
""",
                encoding="utf-8",
            )

            content = generate_default_config(tmpdir)
            assert "check_vulnerabilities = false" in content
            assert "max_packages = 200" in content
