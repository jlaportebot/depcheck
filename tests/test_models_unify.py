"""Tests for unified models in depcheck.models."""

from __future__ import annotations

from depcheck.models import (
    ConflictSeverity,
    LicenseCategory,
    LicenseInfo,
    VersionConstraint,
)


class TestLicenseCategory:
    """Tests for LicenseCategory str-enum."""

    def test_is_str_enum(self) -> None:
        # LicenseCategory should be a str-Enum so LicenseCategory.UNKNOWN == "unknown"
        assert LicenseCategory.UNKNOWN == "unknown"
        assert LicenseCategory.PERMISSIVE == "permissive"
        assert LicenseCategory.COPYLEFT == "copyleft"
        assert LicenseCategory.PUBLIC_DOMAIN == "public_domain"
        assert LicenseCategory.RESTRICTED == "restricted"
        assert LicenseCategory.PROPRIETARY == "proprietary"

    def test_values_are_strings(self) -> None:
        for member in LicenseCategory:
            assert isinstance(member.value, str)

    def test_can_construct_from_string(self) -> None:
        assert LicenseCategory("permissive") == LicenseCategory.PERMISSIVE
        assert LicenseCategory("unknown") == LicenseCategory.UNKNOWN


class TestLicenseInfo:
    """Tests for unified LicenseInfo."""

    def test_category_is_string(self) -> None:
        info = LicenseInfo(spdx_id="MIT", category="permissive")
        assert info.category == "permissive"
        assert isinstance(info.category, str)

    def test_accepts_license_category_enum(self) -> None:
        # Should coerce LicenseCategory enum to its string value
        info = LicenseInfo(spdx_id="MIT", category=LicenseCategory.PERMISSIVE)
        assert info.category == "permissive"
        assert isinstance(info.category, str)

    def test_to_dict_returns_string_category(self) -> None:
        info = LicenseInfo(spdx_id="GPL-3.0", category=LicenseCategory.COPYLEFT)
        d = info.to_dict()
        assert d["category"] == "copyleft"
        assert isinstance(d["category"], str)

    def test_default_category_unknown(self) -> None:
        info = LicenseInfo(spdx_id="MIT")
        assert info.category == "unknown"

    def test_all_fields_present(self) -> None:
        info = LicenseInfo(
            spdx_id="Apache-2.0",
            raw_license="Apache License 2.0",
            category="permissive",
            is_compliant=True,
            compliance_note="OK",
        )
        assert info.spdx_id == "Apache-2.0"
        assert info.raw_license == "Apache License 2.0"
        assert info.category == "permissive"
        assert info.is_compliant is True
        assert info.compliance_note == "OK"


class TestVersionConstraint:
    """Tests for unified VersionConstraint supporting both resolve.py and conflicts.py shapes."""

    def test_resolve_shape(self) -> None:
        # resolve.py shape: package, specifier, source
        vc = VersionConstraint(package="requests", specifier=">=2.28", source="project")
        assert vc.package == "requests"
        assert vc.specifier == ">=2.28"
        assert vc.source == "project"
        assert vc.target == ""  # default empty

    def test_conflicts_shape(self) -> None:
        # conflicts.py shape: package, target, specifier, source
        vc = VersionConstraint(
            package="flask", target="werkzeug", specifier=">=2.0", source="direct"
        )
        assert vc.package == "flask"
        assert vc.target == "werkzeug"
        assert vc.specifier == ">=2.0"
        assert vc.source == "direct"

    def test_to_dict_resolve_shape(self) -> None:
        vc = VersionConstraint(package="foo", specifier=">=1.0", source="bar")
        d = vc.to_dict()
        assert d == {"package": "foo", "specifier": ">=1.0", "source": "bar"}

    def test_to_dict_conflicts_shape(self) -> None:
        vc = VersionConstraint(
            package="flask", target="werkzeug", specifier=">=2.0", source="direct"
        )
        d = vc.to_dict()
        # Must preserve both package and target for conflicts.py compatibility
        assert d["package"] == "flask"
        assert d["target"] == "werkzeug"
        assert d["specifier"] == ">=2.0"
        assert d["source"] == "direct"

    def test_allows_method_works(self) -> None:
        vc = VersionConstraint(package="foo", specifier=">=1.0,<2.0")
        assert vc.allows("1.5") is True
        assert vc.allows("2.0") is False
        assert vc.allows("0.9") is False

    def test_specifier_set_property(self) -> None:
        vc = VersionConstraint(package="foo", specifier=">=1.0")
        ss = vc.specifier_set
        assert "1.5" in ss


class TestConflictSeverity:
    """Tests for unified ConflictSeverity supporting both stack.py and conflicts.py values."""

    def test_has_stack_values(self) -> None:
        assert ConflictSeverity.WARNING == "warning"
        assert ConflictSeverity.ERROR == "error"
        assert ConflictSeverity.CRITICAL == "critical"

    def test_has_conflicts_values(self) -> None:
        assert ConflictSeverity.HARD == "hard"
        assert ConflictSeverity.SOFT == "soft"
        # WARNING is shared

    def test_all_values_are_strings(self) -> None:
        for member in ConflictSeverity:
            assert isinstance(member.value, str)

    def test_can_construct_from_string(self) -> None:
        assert ConflictSeverity("hard") == ConflictSeverity.HARD
        assert ConflictSeverity("warning") == ConflictSeverity.WARNING

    def test_stack_severity_usage(self) -> None:
        # stack.py uses WARNING, ERROR, CRITICAL
        sev = ConflictSeverity.WARNING
        assert sev.value == "warning"

    def test_conflicts_severity_usage(self) -> None:
        # conflicts.py uses HARD, SOFT, WARNING
        sev = ConflictSeverity.HARD
        assert sev.value == "hard"


class TestModelImports:
    """Tests that models can be imported from their original locations."""

    def test_license_info_from_models(self) -> None:
        from depcheck.models import LicenseInfo

        info = LicenseInfo(spdx_id="MIT", category="permissive")
        assert info.category == "permissive"

    def test_license_info_from_licenses(self) -> None:
        from depcheck.licenses import LicenseInfo

        info = LicenseInfo(spdx_id="MIT", category="permissive")
        assert info.category == "permissive"

    def test_version_constraint_from_resolve(self) -> None:
        from depcheck.resolve import VersionConstraint

        vc = VersionConstraint(package="foo", specifier=">=1.0")
        assert vc.package == "foo"

    def test_version_constraint_from_conflicts(self) -> None:
        from depcheck.conflicts import VersionConstraint

        vc = VersionConstraint(package="flask", target="werkzeug", specifier=">=2.0")
        assert vc.target == "werkzeug"

    def test_conflict_severity_from_stack(self) -> None:
        from depcheck.stack import ConflictSeverity

        assert ConflictSeverity.WARNING == "warning"
        assert ConflictSeverity.ERROR == "error"

    def test_conflict_severity_from_conflicts(self) -> None:
        from depcheck.conflicts import ConflictSeverity

        assert ConflictSeverity.HARD == "hard"
        assert ConflictSeverity.SOFT == "soft"
