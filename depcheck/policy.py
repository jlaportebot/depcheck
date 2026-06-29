"""Declarative dependency policy engine for depcheck.

Define and enforce dependency policies via pyproject.toml under
[tool.depcheck.policy] or via CLI flags. Policies specify rules like
"no GPL dependencies", "max age 365 days", "no unpinned deps", and
"max transitive depth 3". Each rule has a severity (error, warning,
info) and the engine produces a pass/fail report with violations.
"""

from __future__ import annotations

import datetime
import enum
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from depcheck.models import HealthStatus, PackageReport
from depcheck.scanner import scan_project

# Package name regex (PEP 503)
_PKG_RE = re.compile(r"^([a-zA-Z0-9][a-zA-Z0-9._-]*)")


# ─── Enums ─────────────────────────────────────────────────────────────────


class RuleSeverity(enum.Enum):
    """Severity level for a policy rule violation."""

    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


class RuleCategory(enum.Enum):
    """Category of a policy rule."""

    LICENSE = "license"
    VERSION = "version"
    AGE = "age"
    PINNING = "pinning"
    DEPTH = "depth"
    VULNERABILITY = "vulnerability"
    MAINTENANCE = "maintenance"
    SIZE = "size"
    CUSTOM = "custom"


# ─── Data Models ───────────────────────────────────────────────────────────


@dataclass
class PolicyRule:
    """A single policy rule."""

    name: str
    category: RuleCategory
    severity: RuleSeverity = RuleSeverity.ERROR
    description: str = ""
    # Rule parameters (interpretation depends on category)
    allow_licenses: list[str] | None = None
    deny_licenses: list[str] | None = None
    deny_copyleft: bool = False
    max_age_days: int | None = None
    require_pinned: bool = False
    max_depth: int | None = None
    max_severity: str | None = None  # Any vuln at or above this severity fails
    min_maintained_days: int | None = None  # Days since last release
    max_size_mb: float | None = None
    allow_packages: list[str] | None = None  # Package allowlist
    deny_packages: list[str] | None = None  # Package denylist
    require_version_min: dict[str, str] | None = None  # pkg → min version
    require_version_max: dict[str, str] | None = None  # pkg → max version
    strict_unknown: bool = False  # Fail on unknown/uncategorized

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "allow_licenses": self.allow_licenses,
            "deny_licenses": self.deny_licenses,
            "deny_copyleft": self.deny_copyleft,
            "max_age_days": self.max_age_days,
            "require_pinned": self.require_pinned,
            "max_depth": self.max_depth,
            "max_severity": self.max_severity,
            "min_maintained_days": self.min_maintained_days,
            "max_size_mb": self.max_size_mb,
            "allow_packages": self.allow_packages,
            "deny_packages": self.deny_packages,
            "strict_unknown": self.strict_unknown,
        }


@dataclass
class Violation:
    """A policy violation for a specific package."""

    rule_name: str
    package: str
    version: str
    severity: RuleSeverity
    category: RuleCategory
    message: str
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "package": self.package,
            "version": self.version,
            "severity": self.severity.value,
            "category": self.category.value,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass
class PolicyReport:
    """Complete policy evaluation report."""

    project_path: str
    rules: list[PolicyRule] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    total_packages: int = 0
    error_count: int = 0
    warning_count: int = 0
    info_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def is_compliant(self) -> bool:
        """Whether the project passes all error-severity rules."""
        return self.error_count == 0

    @property
    def compliance_score(self) -> float:
        """Compliance score as percentage (0–100).

        Based on the ratio of packages without error violations.
        """
        if self.total_packages == 0:
            return 100.0
        failing_pkgs = len(
            set(v.package for v in self.violations if v.severity == RuleSeverity.ERROR)
        )
        return round((1 - failing_pkgs / self.total_packages) * 100, 1)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "is_compliant": self.is_compliant,
            "compliance_score": self.compliance_score,
            "total_packages": self.total_packages,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "info_count": self.info_count,
            "rules": [r.to_dict() for r in self.rules],
            "violations": [v.to_dict() for v in self.violations],
            "errors": self.errors,
        }


# ─── Policy Configuration ──────────────────────────────────────────────────


@dataclass
class PolicyConfig:
    """Full policy configuration that can be loaded from pyproject.toml."""

    rules: list[PolicyRule] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyConfig:
        """Create PolicyConfig from a dictionary (e.g., parsed TOML)."""
        rules: list[PolicyRule] = []

        # Parse license rules
        license_config = data.get("license", {})
        if license_config:
            deny_list = license_config.get("deny", [])
            allow_list = license_config.get("allow", [])
            deny_copyleft = license_config.get("deny_copyleft", False)
            strict_unknown = license_config.get("strict_unknown", False)

            if deny_list or allow_list or deny_copyleft or strict_unknown:
                rules.append(
                    PolicyRule(
                        name="license-policy",
                        category=RuleCategory.LICENSE,
                        severity=RuleSeverity(license_config.get("severity", "error")),
                        description="License compliance policy",
                        allow_licenses=allow_list if allow_list else None,
                        deny_licenses=deny_list if deny_list else None,
                        deny_copyleft=deny_copyleft,
                        strict_unknown=strict_unknown,
                    )
                )

        # Parse version rules
        version_config = data.get("version", {})
        if version_config:
            max_age = version_config.get("max_age_days")
            require_pinned = version_config.get("require_pinned", False)
            min_versions = version_config.get("min_versions", {})
            max_versions = version_config.get("max_versions", {})

            if max_age is not None:
                rules.append(
                    PolicyRule(
                        name="version-age",
                        category=RuleCategory.AGE,
                        severity=RuleSeverity(version_config.get("severity", "warning")),
                        description=f"Dependencies must be updated within {max_age} days",
                        max_age_days=max_age,
                    )
                )

            if require_pinned:
                rules.append(
                    PolicyRule(
                        name="version-pinning",
                        category=RuleCategory.PINNING,
                        severity=RuleSeverity(version_config.get("severity", "error")),
                        description="All dependencies must be pinned to exact versions",
                        require_pinned=True,
                    )
                )

            if min_versions:
                rules.append(
                    PolicyRule(
                        name="version-minimum",
                        category=RuleCategory.VERSION,
                        severity=RuleSeverity(version_config.get("severity", "error")),
                        description="Minimum version requirements",
                        require_version_min=min_versions,
                    )
                )

            if max_versions:
                rules.append(
                    PolicyRule(
                        name="version-maximum",
                        category=RuleCategory.VERSION,
                        severity=RuleSeverity(version_config.get("severity", "warning")),
                        description="Maximum version requirements",
                        require_version_max=max_versions,
                    )
                )

        # Parse vulnerability rules
        vuln_config = data.get("vulnerability", {})
        if vuln_config:
            max_sev = vuln_config.get("max_severity")
            if max_sev:
                rules.append(
                    PolicyRule(
                        name="vulnerability-policy",
                        category=RuleCategory.VULNERABILITY,
                        severity=RuleSeverity(vuln_config.get("severity", "error")),
                        description=f"No vulnerabilities at or above {max_sev} severity",
                        max_severity=max_sev,
                    )
                )

        # Parse maintenance rules
        maint_config = data.get("maintenance", {})
        if maint_config:
            min_days = maint_config.get("min_maintained_days")
            if min_days is not None:
                rules.append(
                    PolicyRule(
                        name="maintenance-policy",
                        category=RuleCategory.MAINTENANCE,
                        severity=RuleSeverity(maint_config.get("severity", "warning")),
                        description=f"Dependencies must have been updated in the last {min_days} days",
                        min_maintained_days=min_days,
                    )
                )

        # Parse depth rules
        depth_config = data.get("depth", {})
        if depth_config:
            max_d = depth_config.get("max_depth")
            if max_d is not None:
                rules.append(
                    PolicyRule(
                        name="depth-policy",
                        category=RuleCategory.DEPTH,
                        severity=RuleSeverity(depth_config.get("severity", "warning")),
                        description=f"Maximum transitive dependency depth: {max_d}",
                        max_depth=max_d,
                    )
                )

        # Parse package denylist/allowlist
        pkg_config = data.get("packages", {})
        if pkg_config:
            deny_pkgs = pkg_config.get("deny", [])
            allow_pkgs = pkg_config.get("allow", [])

            if deny_pkgs:
                rules.append(
                    PolicyRule(
                        name="package-denylist",
                        category=RuleCategory.CUSTOM,
                        severity=RuleSeverity(pkg_config.get("severity", "error")),
                        description="Denied packages",
                        deny_packages=deny_pkgs,
                    )
                )

            if allow_pkgs:
                rules.append(
                    PolicyRule(
                        name="package-allowlist",
                        category=RuleCategory.CUSTOM,
                        severity=RuleSeverity(pkg_config.get("severity", "error")),
                        description="Only allowed packages may be used",
                        allow_packages=allow_pkgs,
                    )
                )

        return cls(rules=rules)

    @classmethod
    def from_pyproject(cls, project_path: Path) -> PolicyConfig | None:
        """Load policy config from [tool.depcheck.policy] in pyproject.toml."""
        pyproject = project_path / "pyproject.toml"
        if not pyproject.is_file():
            return None

        try:
            content = pyproject.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

        if sys.version_info >= (3, 11):
            import tomllib
        else:
            try:
                import tomli as tomllib  # type: ignore[no-redef]
            except ImportError:
                return None

        try:
            data = tomllib.loads(content)
        except Exception:
            return None

        policy_data = data.get("tool", {}).get("depcheck", {}).get("policy")
        if policy_data is None:
            return None

        return cls.from_dict(policy_data)


# ─── Rule Evaluation ───────────────────────────────────────────────────────


# Severity ranking for vulnerability comparison
_SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def _evaluate_license_rule(rule: PolicyRule, pkg: PackageReport) -> Violation | None:
    """Evaluate a license policy rule against a package."""
    if pkg.license_info is None:
        if rule.strict_unknown:
            return Violation(
                rule_name=rule.name,
                package=pkg.name,
                version=pkg.installed_version,
                severity=rule.severity,
                category=rule.category,
                message="License is unknown/uncategorized",
                remediation="Add license info or remove this dependency",
            )
        return None

    spdx = pkg.license_info.spdx_id.upper() if pkg.license_info.spdx_id else ""
    category = pkg.license_info.category.lower() if pkg.license_info.category else "unknown"

    # Check deny list
    if rule.deny_licenses and any(
        d.upper() == spdx or d.lower() == category for d in rule.deny_licenses
    ):
        return Violation(
            rule_name=rule.name,
            package=pkg.name,
            version=pkg.installed_version,
            severity=rule.severity,
            category=rule.category,
            message=f"Denied license: {spdx or category}",
            remediation=f"Remove {pkg.name} or obtain a license exception",
        )

    # Check copyleft denial
    if rule.deny_copyleft and category == "copyleft":
        return Violation(
            rule_name=rule.name,
            package=pkg.name,
            version=pkg.installed_version,
            severity=rule.severity,
            category=rule.category,
            message=f"Copyleft license denied: {spdx}",
            remediation="Replace with a permissively-licensed alternative",
        )

    # Check allow list (if specified, only these are allowed)
    if rule.allow_licenses and not any(
        a.upper() == spdx or a.lower() == category for a in rule.allow_licenses
    ):
        return Violation(
            rule_name=rule.name,
            package=pkg.name,
            version=pkg.installed_version,
            severity=rule.severity,
            category=rule.category,
            message=f"License not in allow list: {spdx or category}",
            remediation=f"Add '{spdx or category}' to allow list or remove {pkg.name}",
        )

    return None


def _evaluate_age_rule(rule: PolicyRule, pkg: PackageReport) -> Violation | None:
    """Evaluate an age policy rule against a package."""
    if rule.max_age_days is None:
        return None

    if not pkg.last_release_date:
        return None  # Can't determine age

    try:
        last_release = datetime.datetime.strptime(pkg.last_release_date, "%Y-%m-%d").replace(
            tzinfo=datetime.timezone.utc
        )
        days_since = (datetime.datetime.now(datetime.timezone.utc) - last_release).days

        if days_since > rule.max_age_days:
            return Violation(
                rule_name=rule.name,
                package=pkg.name,
                version=pkg.installed_version,
                severity=rule.severity,
                category=rule.category,
                message=f"Last release {days_since} days ago (max {rule.max_age_days})",
                remediation=f"Update {pkg.name} or find an actively-maintained alternative",
            )
    except (ValueError, TypeError):
        pass

    return None


def _evaluate_pinning_rule(rule: PolicyRule, pkg: PackageReport) -> Violation | None:
    """Evaluate a version pinning rule against a package."""
    if not rule.require_pinned:
        return None

    if pkg.installed_version == "unknown" or not pkg.installed_version:
        return Violation(
            rule_name=rule.name,
            package=pkg.name,
            version=pkg.installed_version,
            severity=rule.severity,
            category=rule.category,
            message="Dependency not pinned to an exact version",
            remediation=f"Pin {pkg.name} to an exact version (e.g., {pkg.name}==X.Y.Z)",
        )

    return None


def _evaluate_version_rule(rule: PolicyRule, pkg: PackageReport) -> Violation | None:
    """Evaluate minimum/maximum version rules."""
    if rule.require_version_min:
        min_ver = rule.require_version_min.get(pkg.name)
        if min_ver:
            try:
                from packaging.version import Version

                if Version(pkg.installed_version) < Version(min_ver):
                    return Violation(
                        rule_name=rule.name,
                        package=pkg.name,
                        version=pkg.installed_version,
                        severity=rule.severity,
                        category=rule.category,
                        message=f"Version {pkg.installed_version} below minimum {min_ver}",
                        remediation=f"Update {pkg.name} to >= {min_ver}",
                    )
            except Exception:
                pass

    if rule.require_version_max:
        max_ver = rule.require_version_max.get(pkg.name)
        if max_ver:
            try:
                from packaging.version import Version

                if Version(pkg.installed_version) > Version(max_ver):
                    return Violation(
                        rule_name=rule.name,
                        package=pkg.name,
                        version=pkg.installed_version,
                        severity=rule.severity,
                        category=rule.category,
                        message=f"Version {pkg.installed_version} above maximum {max_ver}",
                        remediation=f"Downgrade {pkg.name} to <= {max_ver}",
                    )
            except Exception:
                pass

    return None


def _evaluate_vulnerability_rule(rule: PolicyRule, pkg: PackageReport) -> Violation | None:
    """Evaluate a vulnerability policy rule against a package."""
    if not rule.max_severity or not pkg.vulnerabilities:
        return None

    threshold = _SEV_RANK.get(rule.max_severity.upper(), 0)

    for vuln in pkg.vulnerabilities:
        vuln_rank = _SEV_RANK.get(vuln.severity.upper(), 0)
        if vuln_rank >= threshold:
            return Violation(
                rule_name=rule.name,
                package=pkg.name,
                version=pkg.installed_version,
                severity=rule.severity,
                category=rule.category,
                message=f"Vulnerability {vuln.vuln_id} ({vuln.severity}) at or above threshold {rule.max_severity}",
                remediation=f"Update {pkg.name} to a patched version",
            )

    return None


def _evaluate_maintenance_rule(rule: PolicyRule, pkg: PackageReport) -> Violation | None:
    """Evaluate a maintenance policy rule against a package."""
    if rule.min_maintained_days is None:
        return None

    if pkg.status == HealthStatus.UNMAINTAINED:
        return Violation(
            rule_name=rule.name,
            package=pkg.name,
            version=pkg.installed_version,
            severity=rule.severity,
            category=rule.category,
            message="Package appears unmaintained",
            remediation=f"Consider replacing {pkg.name} with an actively-maintained alternative",
        )

    if pkg.last_release_date:
        try:
            last_release = datetime.datetime.strptime(pkg.last_release_date, "%Y-%m-%d").replace(
                tzinfo=datetime.timezone.utc
            )
            days_since = (datetime.datetime.now(datetime.timezone.utc) - last_release).days

            if days_since > rule.min_maintained_days:
                return Violation(
                    rule_name=rule.name,
                    package=pkg.name,
                    version=pkg.installed_version,
                    severity=rule.severity,
                    category=rule.category,
                    message=f"Last release {days_since} days ago (policy: {rule.min_maintained_days})",
                    remediation=f"Find an alternative to {pkg.name} or verify maintenance",
                )
        except (ValueError, TypeError):
            pass

    return None


def _evaluate_package_rule(rule: PolicyRule, pkg: PackageReport) -> Violation | None:
    """Evaluate a package allowlist/denylist rule."""
    if rule.deny_packages and pkg.name in rule.deny_packages:
        return Violation(
            rule_name=rule.name,
            package=pkg.name,
            version=pkg.installed_version,
            severity=rule.severity,
            category=rule.category,
            message="Package is on the deny list",
            remediation=f"Remove {pkg.name} from your dependencies",
        )

    if rule.allow_packages and pkg.name not in rule.allow_packages:
        return Violation(
            rule_name=rule.name,
            package=pkg.name,
            version=pkg.installed_version,
            severity=rule.severity,
            category=rule.category,
            message="Package not on the allow list",
            remediation=f"Remove {pkg.name} or add it to the allow list",
        )

    return None


def _evaluate_rule(rule: PolicyRule, pkg: PackageReport) -> list[Violation]:
    """Evaluate a single policy rule against a package.

    Returns a list of violations (may be empty).
    """
    violations: list[Violation] = []

    # Dispatch based on category
    evaluators = {
        RuleCategory.LICENSE: _evaluate_license_rule,
        RuleCategory.AGE: _evaluate_age_rule,
        RuleCategory.PINNING: _evaluate_pinning_rule,
        RuleCategory.VERSION: _evaluate_version_rule,
        RuleCategory.VULNERABILITY: _evaluate_vulnerability_rule,
        RuleCategory.MAINTENANCE: _evaluate_maintenance_rule,
        RuleCategory.CUSTOM: _evaluate_package_rule,
    }

    evaluator = evaluators.get(rule.category)
    if evaluator:
        result = evaluator(rule, pkg)
        if result:
            violations.append(result)

    return violations


# ─── Core Logic ────────────────────────────────────────────────────────────


def evaluate_policy(
    project_path: str | Path,
    config: PolicyConfig | None = None,
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
) -> PolicyReport:
    """Evaluate a dependency policy against a project.

    Args:
        project_path: Path to the project directory.
        config: Policy configuration (loaded from pyproject.toml if None).
        check_vulnerabilities: Whether to check for vulnerabilities.
        check_licenses: Whether to check license compliance.

    Returns:
        A PolicyReport with all violations.
    """
    project_path = Path(project_path).resolve()

    if not project_path.is_dir():
        return PolicyReport(
            project_path=str(project_path),
            errors=[f"Path is not a directory: {project_path}"],
        )

    # Load config from pyproject.toml if not provided
    if config is None:
        config = PolicyConfig.from_pyproject(project_path) or PolicyConfig()

    # If no rules defined, add a default set
    if not config.rules:
        config.rules = _default_rules()

    # Scan the project
    scan_result = scan_project(
        project_path=str(project_path),
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
    )

    if scan_result.errors and not scan_result.packages:
        return PolicyReport(
            project_path=str(project_path),
            rules=config.rules,
            errors=scan_result.errors,
        )

    # Evaluate each rule against each package
    all_violations: list[Violation] = []
    for rule in config.rules:
        for pkg in scan_result.packages:
            violations = _evaluate_rule(rule, pkg)
            all_violations.extend(violations)

    # Count violations by severity
    error_count = sum(1 for v in all_violations if v.severity == RuleSeverity.ERROR)
    warning_count = sum(1 for v in all_violations if v.severity == RuleSeverity.WARNING)
    info_count = sum(1 for v in all_violations if v.severity == RuleSeverity.INFO)

    return PolicyReport(
        project_path=str(project_path),
        rules=config.rules,
        violations=all_violations,
        total_packages=len(scan_result.packages),
        error_count=error_count,
        warning_count=warning_count,
        info_count=info_count,
        pass_count=len(scan_result.packages) - len(set(v.package for v in all_violations)),
        fail_count=len(set(v.package for v in all_violations)),
    )


def _default_rules() -> list[PolicyRule]:
    """Return a set of default policy rules."""
    return [
        PolicyRule(
            name="no-critical-vulns",
            category=RuleCategory.VULNERABILITY,
            severity=RuleSeverity.ERROR,
            description="No critical or high severity vulnerabilities allowed",
            max_severity="HIGH",
        ),
        PolicyRule(
            name="no-unmaintained",
            category=RuleCategory.MAINTENANCE,
            severity=RuleSeverity.WARNING,
            description="Warn about unmaintained packages (>365 days since release)",
            min_maintained_days=365,
        ),
    ]


# ─── Rendering ─────────────────────────────────────────────────────────────


def _severity_icon(severity: RuleSeverity) -> str:
    """Get a styled icon for a rule severity."""
    icons = {
        RuleSeverity.ERROR: "[red]✗[/red]",
        RuleSeverity.WARNING: "[yellow]⚠[/yellow]",
        RuleSeverity.INFO: "[blue]ℹ[/blue]",
    }
    return icons.get(severity, "·")


def render_policy_table(report: PolicyReport, console: Console | None = None) -> None:
    """Render policy evaluation report as Rich tables."""
    if console is None:
        console = Console()

    console.print(f"\n[bold]Policy Evaluation: {report.project_path}[/bold]\n")

    # Summary panel
    status = "[green]✓ COMPLIANT[/green]" if report.is_compliant else "[red]✗ NON-COMPLIANT[/red]"
    border = "green" if report.is_compliant else "red"

    summary = (
        f"Status: {status}\n"
        f"Compliance Score: [bold]{report.compliance_score}%[/bold]\n"
        f"Total packages: {report.total_packages}\n"
        f"Errors: {report.error_count}  Warnings: {report.warning_count}  Info: {report.info_count}\n"
        f"Pass: {report.pass_count}  Fail: {report.fail_count}\n"
        f"Active rules: {len(report.rules)}"
    )
    console.print(Panel(summary, title="Policy Summary", border_style=border))

    # Rules table
    if report.rules:
        rules_table = Table(title="Active Policy Rules")
        rules_table.add_column("Rule", style="bold")
        rules_table.add_column("Category")
        rules_table.add_column("Severity")
        rules_table.add_column("Description", max_width=60)

        for rule in report.rules:
            rules_table.add_row(
                rule.name,
                rule.category.value,
                _severity_icon(rule.severity) + f" {rule.severity.value}",
                rule.description,
            )

        console.print(rules_table)

    # Violations table
    if report.violations:
        viol_table = Table(title="Policy Violations", show_lines=True)
        viol_table.add_column("Severity", justify="center")
        viol_table.add_column("Rule")
        viol_table.add_column("Package", style="bold")
        viol_table.add_column("Version")
        viol_table.add_column("Message", max_width=50)
        viol_table.add_column("Remediation", max_width=40)

        # Sort: errors first, then warnings, then info
        sorted_violations = sorted(
            report.violations,
            key=lambda v: (
                0
                if v.severity == RuleSeverity.ERROR
                else 1
                if v.severity == RuleSeverity.WARNING
                else 2
            ),
        )

        for viol in sorted_violations:
            viol_table.add_row(
                _severity_icon(viol.severity),
                viol.rule_name,
                viol.package,
                viol.version,
                viol.message,
                viol.remediation,
            )

        console.print(viol_table)
    else:
        console.print("\n[green]✓ No policy violations found[/green]")


def render_policy_json(report: PolicyReport, console: Console | None = None) -> None:
    """Render policy evaluation report as JSON."""
    output = json.dumps(report.to_dict(), indent=2)
    if console is None:
        console = Console(force_terminal=False, no_color=True)
    console.print(output)
