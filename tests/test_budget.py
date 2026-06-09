"""Tests for depcheck budget module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from depcheck.budget import (
    BudgetConfig,
    BudgetReport,
    BudgetRule,
    _classify_license_simple,
    check_budget,
    init_budget_file,
    render_budget_json,
    render_budget_table,
)

# ── BudgetRule tests ─────────────────────────────────────────────────────


class TestBudgetRule:
    """Tests for BudgetRule dataclass."""

    def test_not_violated(self) -> None:
        rule = BudgetRule(name="test", limit=100, current=50)
        assert rule.is_violated is False

    def test_violated(self) -> None:
        rule = BudgetRule(name="test", limit=100, current=150)
        assert rule.is_violated is True

    def test_at_limit(self) -> None:
        rule = BudgetRule(name="test", limit=100, current=100)
        assert rule.is_violated is False

    def test_utilization(self) -> None:
        rule = BudgetRule(name="test", limit=100, current=75)
        assert rule.utilization == 75.0

    def test_utilization_over_100(self) -> None:
        rule = BudgetRule(name="test", limit=100, current=150)
        assert rule.utilization == 150.0

    def test_utilization_zero_limit(self) -> None:
        rule = BudgetRule(name="test", limit=0, current=10)
        assert rule.utilization == 0.0

    def test_remaining(self) -> None:
        rule = BudgetRule(name="test", limit=100, current=60)
        assert rule.remaining == 40

    def test_remaining_zero_when_violated(self) -> None:
        rule = BudgetRule(name="test", limit=100, current=150)
        assert rule.remaining == 0.0

    def test_to_dict(self) -> None:
        rule = BudgetRule(
            name="Package Count",
            metric="count",
            limit=20,
            current=15,
            unit="packages",
            severity="error",
        )
        d = rule.to_dict()
        assert d["name"] == "Package Count"
        assert d["metric"] == "count"
        assert d["limit"] == 20
        assert d["current"] == 15
        assert d["remaining"] == 5
        assert d["utilization_pct"] == 75.0
        assert d["is_violated"] is False
        assert d["severity"] == "error"

    def test_defaults(self) -> None:
        rule = BudgetRule()
        assert rule.name == ""
        assert rule.metric == ""
        assert rule.limit == 0
        assert rule.current == 0
        assert rule.unit == ""
        assert rule.severity == "error"


# ── BudgetConfig tests ──────────────────────────────────────────────────


class TestBudgetConfig:
    """Tests for BudgetConfig dataclass."""

    def test_defaults(self) -> None:
        config = BudgetConfig()
        assert config.max_packages == 50
        assert config.max_total_download_kb == 500_000
        assert config.max_total_install_kb == 1_000_000
        assert config.max_single_package_kb == 100_000
        assert config.max_transitive_depth == 6
        assert "permissive" in config.allowed_license_categories

    def test_to_dict(self) -> None:
        config = BudgetConfig(max_packages=30)
        d = config.to_dict()
        assert d["max_packages"] == 30
        assert "allowed_license_categories" in d
        assert "denied_packages" in d
        assert "required_packages" in d
        # Sets become sorted lists
        assert isinstance(d["allowed_license_categories"], list)
        assert isinstance(d["denied_packages"], list)
        assert isinstance(d["required_packages"], list)

    def test_from_dict(self) -> None:
        data = {
            "max_packages": 25,
            "max_total_download_kb": 200_000,
            "allowed_license_categories": ["permissive", "public_domain"],
            "denied_packages": ["numpy", "pandas"],
            "required_packages": ["pytest", "ruff"],
        }
        config = BudgetConfig.from_dict(data)
        assert config.max_packages == 25
        assert config.max_total_download_kb == 200_000
        assert "permissive" in config.allowed_license_categories
        assert "numpy" in config.denied_packages
        assert "pytest" in config.required_packages

    def test_from_dict_partial(self) -> None:
        data = {"max_packages": 10}
        config = BudgetConfig.from_dict(data)
        assert config.max_packages == 10
        # Other fields should keep defaults
        assert config.max_total_download_kb == 500_000

    def test_from_dict_empty(self) -> None:
        config = BudgetConfig.from_dict({})
        assert config.max_packages == 50  # Default

    def test_from_file(self, tmp_path: Path) -> None:
        config_data = {"max_packages": 15, "max_total_download_kb": 100_000}
        config_file = tmp_path / "depcheck.budget.json"
        config_file.write_text(json.dumps(config_data))

        config = BudgetConfig.from_file(config_file)
        assert config.max_packages == 15
        assert config.max_total_download_kb == 100_000

    def test_from_file_missing(self, tmp_path: Path) -> None:
        config = BudgetConfig.from_file(tmp_path / "nonexistent.json")
        assert config.max_packages == 50  # Default

    def test_from_file_invalid_json(self, tmp_path: Path) -> None:
        config_file = tmp_path / "bad.json"
        config_file.write_text("not valid json {{{")
        config = BudgetConfig.from_file(config_file)
        assert config.max_packages == 50  # Default

    def test_roundtrip(self) -> None:
        config = BudgetConfig(
            max_packages=30,
            max_total_download_kb=300_000,
            denied_packages={"bad-pkg"},
            required_packages={"pytest"},
        )
        data = config.to_dict()
        restored = BudgetConfig.from_dict(data)
        assert restored.max_packages == 30
        assert "bad-pkg" in restored.denied_packages
        assert "pytest" in restored.required_packages

    def test_from_dict_normalizes_package_names(self) -> None:
        data = {
            "denied_packages": ["My_Package", "Other.Package"],
            "required_packages": ["Cool-Lib"],
        }
        config = BudgetConfig.from_dict(data)
        # Names should be normalized via normalize_package_name
        assert len(config.denied_packages) == 2
        assert len(config.required_packages) == 1


# ── License classification tests ──────────────────────────────────────────


class TestClassifyLicenseSimple:
    """Tests for _classify_license_simple."""

    def test_mit(self) -> None:
        assert _classify_license_simple("MIT") == "permissive"

    def test_apache(self) -> None:
        assert _classify_license_simple("Apache-2.0") == "permissive"

    def test_bsd(self) -> None:
        assert _classify_license_simple("BSD-3-Clause") == "permissive"

    def test_isc(self) -> None:
        assert _classify_license_simple("ISC") == "permissive"

    def test_gpl(self) -> None:
        assert _classify_license_simple("GPL-3.0") == "copyleft"

    def test_agpl(self) -> None:
        assert _classify_license_simple("AGPL-3.0") == "copyleft"

    def test_lgpl(self) -> None:
        assert _classify_license_simple("LGPL-2.1") == "copyleft"

    def test_cc0(self) -> None:
        assert _classify_license_simple("CC0-1.0") == "public_domain"

    def test_unlicense(self) -> None:
        assert _classify_license_simple("Unlicense") == "public_domain"

    def test_proprietary(self) -> None:
        assert _classify_license_simple("Proprietary") == "proprietary"

    def test_commercial(self) -> None:
        assert _classify_license_simple("Commercial") == "proprietary"

    def test_empty(self) -> None:
        assert _classify_license_simple("") == "unknown"

    def test_unknown_string(self) -> None:
        assert _classify_license_simple("SomeWeirdLicense") == "unknown"


# ── BudgetReport tests ───────────────────────────────────────────────────


class TestBudgetReport:
    """Tests for BudgetReport dataclass."""

    def test_compliant_when_no_violations(self) -> None:
        report = BudgetReport(
            rules=[
                BudgetRule(name="r1", limit=100, current=50, severity="error"),
                BudgetRule(name="r2", limit=100, current=80, severity="error"),
            ]
        )
        assert report.is_compliant is True

    def test_non_compliant_with_error_violation(self) -> None:
        report = BudgetReport(
            rules=[
                BudgetRule(name="r1", limit=100, current=50, severity="error"),
                BudgetRule(name="r2", limit=100, current=150, severity="error"),
            ]
        )
        assert report.is_compliant is False

    def test_compliant_with_warning_violation_only(self) -> None:
        report = BudgetReport(
            rules=[
                BudgetRule(name="r1", limit=100, current=150, severity="warning"),
            ]
        )
        assert report.is_compliant is True

    def test_to_dict(self) -> None:
        report = BudgetReport(
            project_path="/tmp/test",
            total_packages=5,
            total_download_kb=1000,
            total_install_kb=2500,
            rules=[
                BudgetRule(name="r1", limit=100, current=50),
            ],
        )
        d = report.to_dict()
        assert d["project_path"] == "/tmp/test"
        assert d["total_packages"] == 5
        assert d["is_compliant"] is True
        assert len(d["rules"]) == 1

    def test_empty_report(self) -> None:
        report = BudgetReport()
        assert report.is_compliant is True
        assert report.rules == []
        assert report.violations == []
        assert report.warnings == []


# ── check_budget tests ──────────────────────────────────────────────────


class TestCheckBudget:
    """Tests for check_budget."""

    def test_invalid_path(self) -> None:
        report = check_budget("/nonexistent/path/xyz")
        # Should have a path violation
        assert len(report.violations) > 0
        assert any(v.metric == "path" for v in report.violations)

    def test_no_dependencies(self, tmp_path: Path) -> None:
        report = check_budget(str(tmp_path))
        # Should have a no-dependencies violation
        assert len(report.violations) > 0
        assert any(v.metric == "count" for v in report.violations)

    @patch("depcheck.budget._fetch_package_size")
    @patch("depcheck.budget.discover_dependencies")
    @patch("depcheck.budget.PyPIClient")
    def test_compliant_project(
        self,
        mock_pypi_cls: MagicMock,
        mock_discover: MagicMock,
        mock_fetch_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        from depcheck.models import ParsedDependency
        from depcheck.size import PackageSize

        mock_discover.return_value = (
            [ParsedDependency(name="flask", version="3.0.0")],
            ["pyproject.toml"],
        )

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = {
            "info": {
                "name": "flask",
                "version": "3.0.0",
                "license": "BSD-3-Clause",
                "classifiers": ["License :: OSI Approved :: BSD License"],
            },
            "releases": {},
        }
        mock_pypi_cls.return_value = mock_pypi

        mock_fetch_size.return_value = PackageSize(
            name="flask",
            version="3.0.0",
            wheel_size_kb=500,
            estimated_install_kb=1250,
            category="small",
        )

        config = BudgetConfig(max_packages=10, max_total_download_kb=500_000)
        report = check_budget(str(tmp_path), config=config)

        assert report.is_compliant is True
        assert report.total_download_kb == 500

    @patch("depcheck.budget._fetch_package_size")
    @patch("depcheck.budget.discover_dependencies")
    @patch("depcheck.budget.PyPIClient")
    def test_violated_package_count(
        self,
        mock_pypi_cls: MagicMock,
        mock_discover: MagicMock,
        mock_fetch_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        from depcheck.models import ParsedDependency
        from depcheck.size import PackageSize

        # Create many dependencies exceeding limit
        deps = [ParsedDependency(name=f"pkg-{i}", version="1.0.0") for i in range(25)]
        mock_discover.return_value = (deps, ["pyproject.toml"])

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = {
            "info": {"name": "pkg", "version": "1.0.0", "license": "MIT", "classifiers": []},
            "releases": {},
        }
        mock_pypi_cls.return_value = mock_pypi

        mock_fetch_size.return_value = PackageSize(
            name="pkg", wheel_size_kb=100, estimated_install_kb=250, category="tiny"
        )

        config = BudgetConfig(max_packages=10)
        report = check_budget(str(tmp_path), config=config)

        # Should have package count violation
        count_rule = next((r for r in report.rules if r.metric == "count"), None)
        assert count_rule is not None
        assert count_rule.is_violated is True

    @patch("depcheck.budget._fetch_package_size")
    @patch("depcheck.budget.discover_dependencies")
    @patch("depcheck.budget.PyPIClient")
    def test_denied_package(
        self,
        mock_pypi_cls: MagicMock,
        mock_discover: MagicMock,
        mock_fetch_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        from depcheck.models import ParsedDependency
        from depcheck.size import PackageSize

        mock_discover.return_value = (
            [ParsedDependency(name="numpy", version="1.24.0")],
            ["pyproject.toml"],
        )

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = {
            "info": {"name": "numpy", "version": "1.24.0", "license": "BSD", "classifiers": []},
            "releases": {},
        }
        mock_pypi_cls.return_value = mock_pypi

        mock_fetch_size.return_value = PackageSize(
            name="numpy", wheel_size_kb=5000, estimated_install_kb=12500, category="medium"
        )

        config = BudgetConfig(denied_packages={"numpy"})
        report = check_budget(str(tmp_path), config=config)

        # Should have denied package violation
        denied_rule = next((r for r in report.rules if r.metric == "denied_packages"), None)
        assert denied_rule is not None
        assert denied_rule.is_violated is True
        assert denied_rule.current == 1

    @patch("depcheck.budget._fetch_package_size")
    @patch("depcheck.budget.discover_dependencies")
    @patch("depcheck.budget.PyPIClient")
    def test_missing_required_package(
        self,
        mock_pypi_cls: MagicMock,
        mock_discover: MagicMock,
        mock_fetch_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        from depcheck.models import ParsedDependency
        from depcheck.size import PackageSize

        mock_discover.return_value = (
            [ParsedDependency(name="flask", version="3.0.0")],
            ["pyproject.toml"],
        )

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = {
            "info": {"name": "flask", "version": "3.0.0", "license": "BSD", "classifiers": []},
            "releases": {},
        }
        mock_pypi_cls.return_value = mock_pypi

        mock_fetch_size.return_value = PackageSize(
            name="flask", wheel_size_kb=500, estimated_install_kb=1250, category="small"
        )

        config = BudgetConfig(required_packages={"pytest", "ruff"})
        report = check_budget(str(tmp_path), config=config)

        # Required packages rule should exist
        required_rule = next((r for r in report.rules if r.metric == "required_packages"), None)
        assert required_rule is not None
        # Current = number of required that are present (0 of 2)
        assert required_rule.current == 0
        assert required_rule.limit == 2

    @patch("depcheck.budget._fetch_package_size")
    @patch("depcheck.budget.discover_dependencies")
    @patch("depcheck.budget.PyPIClient")
    def test_warnings_for_high_utilization(
        self,
        mock_pypi_cls: MagicMock,
        mock_discover: MagicMock,
        mock_fetch_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        from depcheck.models import ParsedDependency
        from depcheck.size import PackageSize

        # 9 packages with limit of 10 = 90% utilization => warning
        deps = [ParsedDependency(name=f"pkg-{i}") for i in range(9)]
        mock_discover.return_value = (deps, ["pyproject.toml"])

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = {
            "info": {"name": "pkg", "version": "1.0.0", "license": "MIT", "classifiers": []},
            "releases": {},
        }
        mock_pypi_cls.return_value = mock_pypi

        mock_fetch_size.return_value = PackageSize(
            name="pkg", wheel_size_kb=100, estimated_install_kb=250, category="tiny"
        )

        config = BudgetConfig(max_packages=10)
        report = check_budget(str(tmp_path), config=config)

        # Should have a warning for high utilization (90%)
        count_warnings = [w for w in report.warnings if w.metric == "count"]
        assert len(count_warnings) > 0
        assert count_warnings[0].utilization == 90.0

    @patch("depcheck.budget._fetch_package_size")
    @patch("depcheck.budget.discover_dependencies")
    @patch("depcheck.budget.PyPIClient")
    def test_license_violation(
        self,
        mock_pypi_cls: MagicMock,
        mock_discover: MagicMock,
        mock_fetch_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        from depcheck.models import ParsedDependency
        from depcheck.size import PackageSize

        mock_discover.return_value = (
            [ParsedDependency(name="gpl-pkg", version="1.0.0")],
            ["pyproject.toml"],
        )

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = {
            "info": {
                "name": "gpl-pkg",
                "version": "1.0.0",
                "license": "GPL-3.0",
                "classifiers": [],
            },
            "releases": {},
        }
        mock_pypi_cls.return_value = mock_pypi

        mock_fetch_size.return_value = PackageSize(
            name="gpl-pkg", wheel_size_kb=100, estimated_install_kb=250, category="tiny"
        )

        # Default allowed: permissive, public_domain — GPL is copyleft
        config = BudgetConfig(allowed_license_categories={"permissive", "public_domain"})
        report = check_budget(str(tmp_path), config=config)

        # Should have license violation (severity=warning)
        license_rule = next((r for r in report.rules if r.metric == "license_category"), None)
        assert license_rule is not None
        assert license_rule.current == 1  # 1 non-compliant license

    @patch("depcheck.budget._fetch_package_size")
    @patch("depcheck.budget.discover_dependencies")
    @patch("depcheck.budget.PyPIClient")
    def test_loads_budget_file(
        self,
        mock_pypi_cls: MagicMock,
        mock_discover: MagicMock,
        mock_fetch_size: MagicMock,
        tmp_path: Path,
    ) -> None:
        from depcheck.models import ParsedDependency
        from depcheck.size import PackageSize

        # Write budget file
        budget_data = {"max_packages": 5, "denied_packages": ["numpy"]}
        budget_file = tmp_path / "depcheck.budget.json"
        budget_file.write_text(json.dumps(budget_data))

        # Write a requirements file so discover_dependencies finds something
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==3.0.0\n")

        mock_discover.return_value = (
            [ParsedDependency(name="flask", version="3.0.0")],
            ["requirements.txt"],
        )

        mock_pypi = MagicMock()
        mock_pypi.__enter__ = MagicMock(return_value=mock_pypi)
        mock_pypi.__exit__ = MagicMock(return_value=False)
        mock_pypi.get_package_info.return_value = {
            "info": {"name": "flask", "version": "3.0.0", "license": "BSD", "classifiers": []},
            "releases": {},
        }
        mock_pypi_cls.return_value = mock_pypi

        mock_fetch_size.return_value = PackageSize(
            name="flask", wheel_size_kb=500, estimated_install_kb=1250, category="small"
        )

        # Pass default config — should be overridden by file
        report = check_budget(str(tmp_path))
        assert report.config.max_packages == 5
        assert "numpy" in report.config.denied_packages


# ── init_budget_file tests ──────────────────────────────────────────────


class TestInitBudgetFile:
    """Tests for init_budget_file."""

    def test_creates_file(self, tmp_path: Path) -> None:
        filepath = init_budget_file(str(tmp_path))
        assert filepath.exists()
        data = json.loads(filepath.read_text())
        assert "max_packages" in data
        assert "max_total_download_kb" in data

    def test_file_is_valid_json(self, tmp_path: Path) -> None:
        filepath = init_budget_file(str(tmp_path))
        content = filepath.read_text()
        data = json.loads(content)
        assert isinstance(data, dict)

    def test_file_has_indentation(self, tmp_path: Path) -> None:
        filepath = init_budget_file(str(tmp_path))
        content = filepath.read_text()
        assert "  " in content  # Should be indented

    def test_returns_path(self, tmp_path: Path) -> None:
        filepath = init_budget_file(str(tmp_path))
        assert filepath.name == "depcheck.budget.json"
        assert filepath.parent == tmp_path.resolve()


# ── Rendering tests ──────────────────────────────────────────────────────


class TestRenderBudgetTable:
    """Tests for render_budget_table."""

    def test_renders_compliant_report(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = BudgetReport(
            project_path="/tmp/test",
            config=BudgetConfig(max_packages=10),
            rules=[
                BudgetRule(
                    name="Package Count",
                    metric="count",
                    limit=10,
                    current=3,
                    unit="packages",
                    severity="error",
                ),
            ],
            total_packages=3,
            total_download_kb=1000,
            total_install_kb=2500,
            package_details=[
                {
                    "name": "flask",
                    "version": "3.0.0",
                    "download_kb": 500,
                    "install_kb": 1250,
                    "category": "small",
                    "license": "BSD",
                    "license_category": "permissive",
                },
            ],
        )

        console = Console(file=StringIO(), width=140)
        render_budget_table(report, console=console)

    def test_renders_violated_report(self) -> None:
        from io import StringIO

        from rich.console import Console

        violated_rule = BudgetRule(
            name="Package Count",
            metric="count",
            limit=5,
            current=10,
            unit="packages",
            severity="error",
        )
        report = BudgetReport(
            project_path="/tmp/test",
            rules=[violated_rule],
            violations=[violated_rule],
            total_packages=10,
        )

        console = Console(file=StringIO(), width=140)
        render_budget_table(report, console=console)

    def test_renders_warnings(self) -> None:
        from io import StringIO

        from rich.console import Console

        warning_rule = BudgetRule(
            name="Download Size",
            metric="download_kb",
            limit=1000,
            current=850,
            unit="KB",
            severity="error",
        )
        report = BudgetReport(
            project_path="/tmp/test",
            rules=[warning_rule],
            warnings=[warning_rule],
            total_download_kb=850,
        )

        console = Console(file=StringIO(), width=140)
        render_budget_table(report, console=console)

    def test_renders_empty_report(self) -> None:
        from io import StringIO

        from rich.console import Console

        report = BudgetReport()
        console = Console(file=StringIO(), width=140)
        render_budget_table(report, console=console)


class TestRenderBudgetJson:
    """Tests for render_budget_json."""

    def test_valid_json(self) -> None:
        report = BudgetReport(
            project_path="/tmp/test",
            total_packages=5,
            total_download_kb=1000,
            rules=[BudgetRule(name="test", limit=100, current=50)],
        )
        json_str = render_budget_json(report)
        data = json.loads(json_str)
        assert data["project_path"] == "/tmp/test"
        assert data["total_packages"] == 5
        assert data["is_compliant"] is True

    def test_violated_report_json(self) -> None:
        violated_rule = BudgetRule(name="test", limit=10, current=20, severity="error")
        report = BudgetReport(
            rules=[violated_rule],
            violations=[violated_rule],
        )
        json_str = render_budget_json(report)
        data = json.loads(json_str)
        assert data["is_compliant"] is False

    def test_includes_config(self) -> None:
        config = BudgetConfig(max_packages=15)
        report = BudgetReport(config=config)
        json_str = render_budget_json(report)
        data = json.loads(json_str)
        assert data["config"]["max_packages"] == 15
