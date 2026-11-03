"""CI gate for depcheck.

Runs a dependency scan and evaluates budget/policy checks to produce
a pass/fail verdict suitable for CI pipelines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from depcheck.budget import BudgetConfig, BudgetReport, check_budget
from depcheck.models import ScanResult
from depcheck.policy import PolicyConfig, PolicyReport, evaluate_policy
from depcheck.scanner import scan_project


@dataclass
class CIGateResult:
    """Result of a CI gate evaluation."""

    project_path: str
    verdict: str  # "pass", "fail", "error"
    failed_checks: list[str] = field(default_factory=list)
    passed_checks: list[str] = field(default_factory=list)
    scan_result: ScanResult | None = None
    budget_report: BudgetReport | None = None
    policy_report: PolicyReport | None = None
    errors: list[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "project_path": self.project_path,
            "verdict": self.verdict,
            "failed_checks": self.failed_checks,
            "passed_checks": self.passed_checks,
            "scan_result": self.scan_result.to_dict() if self.scan_result else None,
            "budget_report": self.budget_report.to_dict() if self.budget_report else None,
            "policy_report": self.policy_report.to_dict() if self.policy_report else None,
            "errors": self.errors,
            "summary": self.summary,
        }


def _load_budget_config(project_path: Path) -> BudgetConfig | None:
    """Load budget configuration from pyproject.toml if present."""
    try:
        return BudgetConfig.from_pyproject(project_path)
    except Exception:
        return None


def _load_policy_config(project_path: Path) -> PolicyConfig | None:
    """Load policy configuration from pyproject.toml if present."""
    try:
        return PolicyConfig.from_pyproject(project_path)
    except Exception:
        return None


def run_ci_gate(
    project_path: str | Path,
    *,
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
    fail_on: str = "vulnerable",
    enforce_budget: bool = False,
    enforce_policy: bool = False,
) -> CIGateResult:
    """Run the CI gate: scan project and evaluate checks.

    Runs the scan ONCE, then evaluates budget and policy only when
    requested AND configured.

    Args:
        project_path: Path to the project directory.
        check_vulnerabilities: Whether to check for vulnerabilities in scan.
        check_licenses: Whether to check licenses in scan.
        fail_on: What severity to fail on ("vulnerable", "outdated", etc.).
        enforce_budget: Whether to enforce budget limits.
        enforce_policy: Whether to enforce policy rules.

    Returns:
        A CIGateResult with the verdict and detailed reports.
    """
    project_path = Path(project_path).resolve()
    resolved_path = str(project_path)

    result = CIGateResult(
        project_path=resolved_path,
        verdict="pass",
        scan_result=None,
    )

    # Run the scan
    try:
        scan_result = scan_project(
            project_path=str(project_path),
            check_vulnerabilities=check_vulnerabilities,
            check_licenses=check_licenses,
        )
        result.scan_result = scan_result
    except Exception as e:
        result.verdict = "error"
        result.errors.append(f"Scan failed: {e}")
        result.summary = f"Scan error: {e}"
        return result

    # Handle scan errors
    if scan_result.errors and not scan_result.packages:
        result.verdict = "error"
        result.errors.extend(scan_result.errors)
        result.summary = f"Scan errors: {', '.join(scan_result.errors)}"
        return result

    # Check vulnerabilities
    if check_vulnerabilities:
        if scan_result.has_vulnerabilities():
            if fail_on in ("vulnerable", "any"):
                result.verdict = "fail"
                result.failed_checks.append("vulnerable")
            else:
                result.passed_checks.append("vulnerable")
                result.passed_checks.append("scan")
        else:
            result.passed_checks.append("vulnerable")
            result.passed_checks.append("scan")

    # Check licenses
    if check_licenses:
        if scan_result.license_issues_count > 0:
            if fail_on in ("license", "any"):
                result.verdict = "fail"
                result.failed_checks.append("licenses")
            else:
                result.passed_checks.append("licenses")
        else:
            result.passed_checks.append("licenses")

    # Check outdated
    if scan_result.outdated_count > 0:
        if fail_on in ("outdated", "any"):
            result.verdict = "fail"
            result.failed_checks.append("outdated")
        else:
            result.passed_checks.append("outdated")
    else:
        result.passed_checks.append("outdated")

    # Enforce budget if requested
    if enforce_budget:
        try:
            budget_config = _load_budget_config(project_path)
            if budget_config and any(
                [
                    budget_config.total,
                    budget_config.direct,
                    budget_config.transitive,
                    budget_config.dev,
                    budget_config.optional,
                    budget_config.groups,
                ]
            ):
                budget_report = check_budget(project_path, config=budget_config)
                result.budget_report = budget_report
                if not budget_report.is_within_budget:
                    result.verdict = "fail"
                    result.failed_checks.append("budget")
                else:
                    result.passed_checks.append("budget")
            else:
                result.passed_checks.append("budget (no config)")
        except Exception as e:
            result.errors.append(f"Budget check failed: {e}")
            result.failed_checks.append("budget (error)")

    # Enforce policy if requested
    if enforce_policy:
        try:
            policy_config = _load_policy_config(project_path)
            if policy_config and policy_config.rules:
                policy_report = evaluate_policy(project_path, config=policy_config)
                result.policy_report = policy_report
                if not policy_report.is_compliant:
                    result.verdict = "fail"
                    result.failed_checks.append("policy")
                else:
                    result.passed_checks.append("policy")
            else:
                result.passed_checks.append("policy (no config)")
        except Exception as e:
            result.errors.append(f"Policy check failed: {e}")
            result.failed_checks.append("policy (error)")

    # Build summary
    if result.verdict == "pass":
        result.summary = "All checks passed"
    elif result.verdict == "fail":
        result.summary = f"Failed checks: {', '.join(result.failed_checks)}"
    else:
        result.summary = f"Errors: {', '.join(result.errors)}"

    return result


def determine_gate_exit_code(result: CIGateResult) -> int:
    """Determine the exit code for a CI gate result.

    Args:
        result: The CI gate result.

    Returns:
        0 for pass, 1 for failed checks, 2 for error.
    """
    if result.verdict == "pass":
        return 0
    if result.verdict == "fail":
        return 1
    return 2
