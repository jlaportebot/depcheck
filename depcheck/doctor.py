"""Project health doctor — checks for best practices and suggests improvements."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class DoctorCheck:
    """A single doctor check result."""

    name: str
    passed: bool
    message: str
    severity: str = "info"  # "error", "warning", "info"
    fix_hint: str | None = None


@dataclass
class DoctorResult:
    """Complete doctor check results."""

    project_path: Path
    checks: list[DoctorCheck] = field(default_factory=list)

    @property
    def passed_count(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def failed_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed)

    @property
    def error_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed and c.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.checks if not c.passed and c.severity == "warning")

    @property
    def overall_status(self) -> str:
        if self.error_count > 0:
            return "error"
        if self.warning_count > 0:
            return "warning"
        return "pass"


def check_ci_workflows(project_path: Path) -> DoctorCheck:
    """Check for CI workflow files."""
    workflows_dir = project_path / ".github" / "workflows"
    if not workflows_dir.exists():
        return DoctorCheck(
            name="CI Workflows",
            passed=False,
            message="No .github/workflows directory found",
            severity="warning",
            fix_hint="Create CI workflow files in .github/workflows/ (e.g., ci.yml)",
        )

    workflow_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))
    if not workflow_files:
        return DoctorCheck(
            name="CI Workflows",
            passed=False,
            message=".github/workflows exists but contains no workflow files",
            severity="warning",
            fix_hint="Add workflow YAML files (e.g., ci.yml) to .github/workflows/",
        )

    return DoctorCheck(
        name="CI Workflows",
        passed=True,
        message=f"Found {len(workflow_files)} workflow file(s)",
    )


def check_pre_commit_config(project_path: Path) -> DoctorCheck:
    """Check for pre-commit or prek configuration."""
    pre_commit = project_path / ".pre-commit-config.yaml"
    prek = project_path / ".prek.toml"

    if pre_commit.exists() or prek.exists():
        configs = []
        if pre_commit.exists():
            configs.append("pre-commit")
        if prek.exists():
            configs.append("prek")
        return DoctorCheck(
            name="Pre-commit Hooks",
            passed=True,
            message=f"Found {', '.join(configs)} configuration",
        )

    return DoctorCheck(
        name="Pre-commit Hooks",
        passed=False,
        message="No pre-commit or prek configuration found",
        severity="info",
        fix_hint=(
            "Add .prek.toml for fast Rust-based hooks or .pre-commit-config.yaml for Python hooks"
        ),
    )


def check_dependabot_config(project_path: Path) -> DoctorCheck:
    """Check for Dependabot configuration."""
    dependabot = project_path / ".github" / "dependabot.yml"
    if dependabot.exists():
        return DoctorCheck(
            name="Dependabot",
            passed=True,
            message="Found dependabot.yml configuration",
        )

    return DoctorCheck(
        name="Dependabot",
        passed=False,
        message="No Dependabot configuration found",
        severity="info",
        fix_hint="Create .github/dependabot.yml to enable automated dependency updates",
    )


def check_security_files(project_path: Path) -> DoctorCheck:
    """Check for security-related files."""
    security_md = project_path / "SECURITY.md"
    code_of_conduct = project_path / "CODE_OF_CONDUCT.md"

    found = []
    missing = []

    if security_md.exists():
        found.append("SECURITY.md")
    else:
        missing.append("SECURITY.md")

    if code_of_conduct.exists():
        found.append("CODE_OF_CONDUCT.md")
    else:
        missing.append("CODE_OF_CONDUCT.md")

    if not missing:
        return DoctorCheck(
            name="Security Files",
            passed=True,
            message=f"Found {', '.join(found)}",
        )

    return DoctorCheck(
        name="Security Files",
        passed=False,
        message=f"Missing: {', '.join(missing)}",
        severity="info",
        fix_hint=(
            "Add SECURITY.md for vulnerability reporting"
            " and CODE_OF_CONDUCT.md for community standards"
        ),
    )


def check_license_file(project_path: Path) -> DoctorCheck:
    """Check for LICENSE file."""
    license_files = list(project_path.glob("LICENSE*")) + list(project_path.glob("LICENCE*"))
    if license_files:
        return DoctorCheck(
            name="License",
            passed=True,
            message=f"Found {license_files[0].name}",
        )

    return DoctorCheck(
        name="License",
        passed=False,
        message="No LICENSE file found",
        severity="warning",
        fix_hint="Add a LICENSE file (MIT, Apache-2.0, etc.)",
    )


def check_readme(project_path: Path) -> DoctorCheck:
    """Check for README file."""
    readme_files = list(project_path.glob("README*")) + list(project_path.glob("readme*"))
    if readme_files:
        return DoctorCheck(
            name="README",
            passed=True,
            message=f"Found {readme_files[0].name}",
        )

    return DoctorCheck(
        name="README",
        passed=False,
        message="No README file found",
        severity="warning",
        fix_hint="Add a README.md with project description and usage",
    )


def check_contributing(project_path: Path) -> DoctorCheck:
    """Check for CONTRIBUTING.md."""
    contributing = project_path / "CONTRIBUTING.md"
    if contributing.exists():
        return DoctorCheck(
            name="Contributing Guide",
            passed=True,
            message="Found CONTRIBUTING.md",
        )

    return DoctorCheck(
        name="Contributing Guide",
        passed=False,
        message="No CONTRIBUTING.md found",
        severity="info",
        fix_hint="Add CONTRIBUTING.md with contribution guidelines",
    )


def check_codeowners(project_path: Path) -> DoctorCheck:
    """Check for CODEOWNERS file."""
    codeowners = project_path / ".github" / "CODEOWNERS"
    if codeowners.exists():
        return DoctorCheck(
            name="CODEOWNERS",
            passed=True,
            message="Found .github/CODEOWNERS",
        )

    # Also check root CODEOWNERS
    codeowners_root = project_path / "CODEOWNERS"
    if codeowners_root.exists():
        return DoctorCheck(
            name="CODEOWNERS",
            passed=True,
            message="Found CODEOWNERS at repository root",
        )

    return DoctorCheck(
        name="CODEOWNERS",
        passed=False,
        message="No CODEOWNERS file found",
        severity="info",
        fix_hint="Add .github/CODEOWNERS to define code owners for automatic review assignment",
    )


def check_pyproject_toml(project_path: Path) -> DoctorCheck:
    """Check for pyproject.toml with essential metadata."""
    pyproject = project_path / "pyproject.toml"
    if not pyproject.exists():
        return DoctorCheck(
            name="pyproject.toml",
            passed=False,
            message="No pyproject.toml found",
            severity="error",
            fix_hint="Create pyproject.toml with [project] metadata",
        )

    try:
        import tomllib

        content = pyproject.read_text(encoding="utf-8")
        data = tomllib.loads(content)
        project = data.get("project", {})

        required_fields = ["name", "version", "description", "requires-python"]
        missing = [f for f in required_fields if f not in project]

        if missing:
            return DoctorCheck(
                name="pyproject.toml",
                passed=False,
                message=f"Missing required fields: {', '.join(missing)}",
                severity="warning",
                fix_hint=f"Add missing fields to [project] section: {', '.join(missing)}",
            )

        return DoctorCheck(
            name="pyproject.toml",
            passed=True,
            message="Found pyproject.toml with required metadata",
        )
    except Exception as e:
        return DoctorCheck(
            name="pyproject.toml",
            passed=False,
            message=f"Failed to parse pyproject.toml: {e}",
            severity="error",
            fix_hint="Fix pyproject.toml syntax",
        )


def check_gitignore(project_path: Path) -> DoctorCheck:
    """Check for .gitignore."""
    gitignore = project_path / ".gitignore"
    if gitignore.exists():
        return DoctorCheck(
            name=".gitignore",
            passed=True,
            message="Found .gitignore",
        )

    return DoctorCheck(
        name=".gitignore",
        passed=False,
        message="No .gitignore found",
        severity="warning",
        fix_hint="Add .gitignore to exclude build artifacts, venv, etc.",
    )


def check_pytest_config(project_path: Path) -> DoctorCheck:
    """Check for pytest configuration."""
    pyproject = project_path / "pyproject.toml"
    pytest_ini = project_path / "pytest.ini"
    setup_cfg = project_path / "setup.cfg"

    has_config = False
    for config_file in [pyproject, pytest_ini, setup_cfg]:
        if config_file.exists():
            try:
                if config_file == pyproject:
                    import tomllib

                    content = config_file.read_text(encoding="utf-8")
                    data = tomllib.loads(content)
                    if "tool" in data and "pytest" in data["tool"]:
                        has_config = True
                        break
                else:
                    content = config_file.read_text(encoding="utf-8")
                    if "[pytest]" in content or "[tool:pytest]" in content:
                        has_config = True
                        break
            except Exception:
                continue

    if has_config:
        return DoctorCheck(
            name="Test Configuration",
            passed=True,
            message="Found pytest configuration",
        )

    # Check if tests directory exists
    tests_dir = project_path / "tests"
    if tests_dir.exists() and tests_dir.is_dir():
        return DoctorCheck(
            name="Test Configuration",
            passed=True,
            message="Found tests/ directory (pytest config may be implicit)",
        )

    return DoctorCheck(
        name="Test Configuration",
        passed=False,
        message="No pytest configuration or tests/ directory found",
        severity="info",
        fix_hint="Add pytest config to pyproject.toml or create tests/ directory",
    )


def run_doctor_checks(project_path: Path | str = ".") -> DoctorResult:
    """Run all doctor checks on a project."""
    path = Path(project_path).resolve()

    checks = [
        check_pyproject_toml(path),
        check_readme(path),
        check_license_file(path),
        check_gitignore(path),
        check_ci_workflows(path),
        check_pre_commit_config(path),
        check_dependabot_config(path),
        check_security_files(path),
        check_contributing(path),
        check_codeowners(path),
        check_pytest_config(path),
    ]

    return DoctorResult(project_path=path, checks=checks)


def render_doctor_result(result: DoctorResult, json_output: bool = False) -> str:
    """Render doctor results as text or JSON."""
    if json_output:
        import json

        return json.dumps(
            {
                "project_path": str(result.project_path),
                "overall_status": result.overall_status,
                "summary": {
                    "total": len(result.checks),
                    "passed": result.passed_count,
                    "failed": result.failed_count,
                    "errors": result.error_count,
                    "warnings": result.warning_count,
                },
                "checks": [
                    {
                        "name": c.name,
                        "passed": c.passed,
                        "message": c.message,
                        "severity": c.severity,
                        "fix_hint": c.fix_hint,
                    }
                    for c in result.checks
                ],
            },
            indent=2,
        )

    # Text output
    lines = [
        f"Project: {result.project_path}",
        f"Status: {result.overall_status.upper()}",
        f"Checks: {result.passed_count}/{len(result.checks)} passed",
        f"Errors: {result.error_count}, Warnings: {result.warning_count}",
        "",
    ]

    for check in result.checks:
        status_icon = "✓" if check.passed else "✗"
        severity_marker = ""
        if not check.passed:
            if check.severity == "error":
                severity_marker = " [ERROR]"
            elif check.severity == "warning":
                severity_marker = " [WARN]"
            else:
                severity_marker = " [INFO]"

        lines.append(f"  {status_icon} {check.name}{severity_marker}")
        lines.append(f"      {check.message}")
        if check.fix_hint and not check.passed:
            lines.append(f"      → Fix: {check.fix_hint}")

    return "\n".join(lines)
