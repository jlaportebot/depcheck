"""Configuration management for depcheck.

Handles loading, merging, and validating configuration from pyproject.toml,
environment variables, and CLI flags. Provides a unified Config object
with defaults for all depcheck subcommands.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from depcheck.budget import BudgetConfig
from depcheck.policy import PolicyConfig

#: Environment variable prefix for depcheck configuration overrides.
DEPCHECK_ENV_PREFIX = "DEPCHECK_"

#: Map environment variable names to ``(section, key)`` overrides on the config.
#: Section is one of ``scan``, ``budget``, or ``policy``.
ENV_OVERRIDES: dict[str, tuple[str, str]] = {
    "DEPCHECK_CHECK_VULNERABILITIES": ("scan", "check_vulnerabilities"),
    "DEPCHECK_CHECK_LICENSES": ("scan", "check_licenses"),
    "DEPCHECK_FAIL_ON": ("scan", "fail_on"),
    "DEPCHECK_QUIET": ("scan", "quiet"),
    "DEPCHECK_OUTPUT_JSON": ("scan", "output_json"),
}


@dataclass
class ScanConfig:
    """Configuration for the scan command."""

    check_vulnerabilities: bool = True
    check_licenses: bool = False
    allowed_license_categories: list[str] = field(default_factory=list)
    denied_licenses: list[str] = field(default_factory=list)
    fail_on: str | None = None
    quiet: bool = False
    output_json: bool = False


@dataclass
class Config:
    """Complete depcheck configuration."""

    scan: ScanConfig = field(default_factory=ScanConfig)
    budget: BudgetConfig = field(default_factory=BudgetConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    project_path: Path = field(default_factory=Path.cwd)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        policy_dict: dict[str, Any] = {}
        if hasattr(self.policy, "to_dict"):
            policy_dict = self.policy.to_dict()  # type: ignore[attr-defined]
        elif hasattr(self.policy, "rules"):
            policy_dict = {"rules": [r.to_dict() for r in self.policy.rules]}  # type: ignore[attr-defined]
        return {
            "scan": {
                "check_vulnerabilities": self.scan.check_vulnerabilities,
                "check_licenses": self.scan.check_licenses,
                "allowed_license_categories": self.scan.allowed_license_categories,
                "denied_licenses": self.scan.denied_licenses,
                "fail_on": self.scan.fail_on,
                "quiet": self.scan.quiet,
                "output_json": self.scan.output_json,
            },
            "budget": self.budget.to_dict() if hasattr(self.budget, "to_dict") else {},  # type: ignore[attr-defined]
            "policy": policy_dict,
            "project_path": str(self.project_path),
        }

    @classmethod
    def load(
        cls,
        project_path: Path | str = ".",
        config_path: Path | str | None = None,
        cli_overrides: dict[str, Any] | None = None,
    ) -> Config:
        """Load configuration from pyproject.toml and apply CLI overrides.

        Args:
            project_path: Project directory (used to locate the default config).
            config_path: Explicit config file to load instead of the default
                ``<project_path>/pyproject.toml``.
            cli_overrides: Overrides applied after file/environment values.
                CLI flags always win.
        """
        path = Path(project_path).resolve()
        if config_path is not None:
            pyproject_path = Path(config_path)
        else:
            pyproject_path = path / "pyproject.toml"

        config = cls(project_path=path)

        # Load from the config file if it exists
        if pyproject_path.is_file():
            try:
                content = pyproject_path.read_text(encoding="utf-8")
                data = tomllib.loads(content)
                depcheck_data = data.get("tool", {}).get("depcheck", {})

                # Parse scan config
                scan_data = depcheck_data.get("scan", {})
                if scan_data:
                    config.scan = ScanConfig(
                        check_vulnerabilities=scan_data.get("check_vulnerabilities", True),
                        check_licenses=scan_data.get("check_licenses", False),
                        allowed_license_categories=scan_data.get("allowed_license_categories", []),
                        denied_licenses=scan_data.get("denied_licenses", []),
                        fail_on=scan_data.get("fail_on"),
                        quiet=scan_data.get("quiet", False),
                        output_json=scan_data.get("output_json", False),
                    )

                # Parse budget config
                budget_data = depcheck_data.get("budget")
                if budget_data:
                    config.budget = BudgetConfig.from_dict(budget_data)

                # Parse policy config
                policy_data = depcheck_data.get("policy")
                if policy_data:
                    config.policy = PolicyConfig.from_dict(policy_data)

            except Exception:
                # Silently ignore parse errors - use defaults
                pass

        # Environment variables override file values (DEPCHECK_* namespace).
        apply_env_overrides(config)

        # Apply CLI overrides last so command-line flags always win.
        if cli_overrides:
            _apply_overrides(config, cli_overrides)

        return config


def _env_bool(raw: str) -> bool:
    """Return whether an environment variable string holds a truthy value."""
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def apply_env_overrides(config: Config) -> None:
    """Apply ``DEPCHECK_*`` environment variables to a config object.

    Environment variables take precedence over values loaded from the config
    file but are overridden by explicit CLI flags (applied separately).

    Args:
        config: The config object to update in place.
    """
    for env_name, (section, key) in ENV_OVERRIDES.items():
        raw = os.environ.get(env_name)
        if raw is None:
            continue
        section_obj = getattr(config, section)
        if not hasattr(section_obj, key):
            continue
        current = getattr(section_obj, key)
        if isinstance(current, bool):
            value = _env_bool(raw)
        else:
            value = raw
        setattr(section_obj, key, value)


def load_config(
    project_path: Path | str = ".",
    config_path: Path | str | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> Config:
    """Load configuration from pyproject.toml and apply CLI overrides."""
    return Config.load(project_path, config_path=config_path, cli_overrides=cli_overrides)


def _apply_overrides(config: Config, overrides: dict[str, Any]) -> None:
    """Apply CLI overrides to config object."""
    scan_overrides = overrides.get("scan", {})
    for key, value in scan_overrides.items():
        if hasattr(config.scan, key) and value is not None:
            setattr(config.scan, key, value)

    budget_overrides = overrides.get("budget", {})
    for key, value in budget_overrides.items():
        if hasattr(config.budget, key) and value is not None:
            setattr(config.budget, key, value)

    policy_overrides = overrides.get("policy", {})
    for key, value in policy_overrides.items():
        if hasattr(config.policy, key) and value is not None:
            setattr(config.policy, key, value)


def validate_config(config: Config) -> list[str]:
    """Validate configuration and return list of warnings/errors."""
    errors = []
    warnings = []

    # Validate scan config
    if config.scan.fail_on:
        valid_fail_on = {"vulnerable", "outdated", "unmaintained", "license", "any"}
        if config.scan.fail_on.lower() not in valid_fail_on:
            errors.append(
                f"scan.fail_on: invalid value '{config.scan.fail_on}', "
                f"must be one of {sorted(valid_fail_on)}"
            )

    # Validate budget config
    if config.budget.total is not None and config.budget.total < 0:
        errors.append("budget.total: must be non-negative")
    if config.budget.direct is not None and config.budget.direct < 0:
        errors.append("budget.direct: must be non-negative")
    if config.budget.transitive is not None and config.budget.transitive < 0:
        errors.append("budget.transitive: must be non-negative")
    if config.budget.dev is not None and config.budget.dev < 0:
        errors.append("budget.dev: must be non-negative")
    if config.budget.optional is not None and config.budget.optional < 0:
        errors.append("budget.optional: must be non-negative")

    # Validate policy config
    for rule in config.policy.rules:
        is_license_rule = rule.category.value == "license"
        no_allow = not rule.allow_licenses
        no_deny = not rule.deny_licenses
        no_copyleft_deny = not rule.deny_copyleft
        if is_license_rule and no_allow and no_deny and no_copyleft_deny:
            warnings.append(f"policy rule '{rule.name}': license rule with no constraints")

    return errors + warnings


def generate_default_config(project_path: Path | str = ".") -> str:
    """Generate a default depcheck configuration as TOML string."""
    path = Path(project_path).resolve()
    pyproject_path = path / "pyproject.toml"

    # Check if pyproject.toml exists and has depcheck config
    existing = {}
    if pyproject_path.is_file():
        try:
            content = pyproject_path.read_text(encoding="utf-8")
            data = tomllib.loads(content)
            existing = data.get("tool", {}).get("depcheck", {})
        except Exception:
            pass

    # Extract existing values with defaults
    scan_existing = existing.get("scan", {})
    budget_existing = existing.get("budget", {})

    check_vuln = str(scan_existing.get("check_vulnerabilities", True)).lower()
    check_lic = str(scan_existing.get("check_licenses", False)).lower()
    allowed_scan = scan_existing.get("allowed_license_categories", ["permissive", "public_domain"])
    denied_scan = scan_existing.get("denied_licenses", [])
    fail_on = repr(scan_existing.get("fail_on"))

    max_pkg = budget_existing.get("max_packages", 50)
    max_dl_kb = budget_existing.get("max_total_download_kb", 500000)
    max_il_kb = budget_existing.get("max_total_install_kb", 1000000)
    max_sp_kb = budget_existing.get("max_single_package_kb", 100000)
    max_depth = budget_existing.get("max_transitive_depth", 6)
    allowed_budget = budget_existing.get(
        "allowed_license_categories", ["permissive", "public_domain"]
    )
    denied_pkg = budget_existing.get("denied_packages", [])
    required_pkg = budget_existing.get("required_packages", [])

    lines = [
        "[tool.depcheck]",
        "",
        "# Scan configuration",
        "[tool.depcheck.scan]",
        f"check_vulnerabilities = {check_vuln}",
        f"check_licenses = {check_lic}",
        f"allowed_license_categories = {allowed_scan}",
        f"denied_licenses = {denied_scan}",
        f"fail_on = {fail_on}",
        "",
        "# Budget configuration",
        "[tool.depcheck.budget]",
        f"max_packages = {max_pkg}",
        f"max_total_download_kb = {max_dl_kb}",
        f"max_total_install_kb = {max_il_kb}",
        f"max_single_package_kb = {max_sp_kb}",
        f"max_transitive_depth = {max_depth}",
        f"allowed_license_categories = {allowed_budget}",
        f"denied_packages = {denied_pkg}",
        f"required_packages = {required_pkg}",
        "",
        "# Policy configuration",
        "[tool.depcheck.policy]",
        "# Example rule:",
        "# [[tool.depcheck.policy.rules]]",
        '# name = "no-copyleft"',
        '# category = "license"',
        '# severity = "error"',
        "# deny_copyleft = true",
        "",
    ]

    return "\n".join(lines) + "\n"
