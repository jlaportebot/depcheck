"""Tests for depcheck license compliance module."""

from __future__ import annotations

from depcheck.licenses import (
    LicenseCategory,
    LicenseInfo,
    check_license_compliance,
    classify_license,
    normalize_license_id,
    normalize_single_id,
    parse_license_from_pypi,
)
from depcheck.models import LicenseInfo as ModelLicenseInfo


class TestNormalizeLicenseId:
    """Tests for license ID normalization."""

    def test_spdx_id_unchanged(self) -> None:
        assert normalize_license_id("MIT") == "MIT"
        assert normalize_license_id("Apache-2.0") == "Apache-2.0"
        assert normalize_license_id("BSD-3-Clause") == "BSD-3-Clause"

    def test_alias_mit_license(self) -> None:
        assert normalize_license_id("MIT License") == "MIT"

    def test_alias_apache(self) -> None:
        assert normalize_license_id("Apache License 2.0") == "Apache-2.0"

    def test_case_insensitive(self) -> None:
        assert normalize_license_id("mit") == "MIT"
        assert normalize_license_id("apache 2.0") == "Apache-2.0"
        assert normalize_license_id("bsd-3-clause") == "BSD-3-Clause"

    def test_or_expression_prefers_permissive(self) -> None:
        result = normalize_license_id("MIT OR GPL-3.0")
        assert result == "MIT"

    def test_or_expression_first_if_no_permissive(self) -> None:
        result = normalize_license_id("GPL-2.0 OR GPL-3.0")
        assert result in ("GPL-2.0", "GPL-3.0")

    def test_and_expression_takes_first(self) -> None:
        result = normalize_license_id("MIT AND BSD-3-Clause")
        assert result == "MIT"

    def test_empty_string(self) -> None:
        assert normalize_license_id("") == ""

    def test_unknown_placeholder(self) -> None:
        assert normalize_license_id("UNKNOWN") == ""
        assert normalize_license_id("N/A") == ""

    def test_strips_plus(self) -> None:
        result = normalize_license_id("GPL-2.0+")
        assert result == "GPL-2.0"

    def test_strips_parentheses(self) -> None:
        result = normalize_license_id("(MIT)")
        assert result == "MIT"


class TestClassifyLicense:
    """Tests for license classification."""

    def test_permissive_licenses(self) -> None:
        assert classify_license("MIT") == LicenseCategory.PERMISSIVE
        assert classify_license("Apache-2.0") == LicenseCategory.PERMISSIVE
        assert classify_license("BSD-2-Clause") == LicenseCategory.PERMISSIVE
        assert classify_license("BSD-3-Clause") == LicenseCategory.PERMISSIVE
        assert classify_license("ISC") == LicenseCategory.PERMISSIVE

    def test_copyleft_licenses(self) -> None:
        assert classify_license("GPL-2.0") == LicenseCategory.COPYLEFT
        assert classify_license("GPL-3.0") == LicenseCategory.COPYLEFT
        assert classify_license("AGPL-3.0") == LicenseCategory.COPYLEFT
        assert classify_license("LGPL-3.0") == LicenseCategory.COPYLEFT
        assert classify_license("MPL-2.0") == LicenseCategory.COPYLEFT

    def test_public_domain(self) -> None:
        assert classify_license("CC0-1.0") == LicenseCategory.PUBLIC_DOMAIN
        assert classify_license("Unlicense") == LicenseCategory.PUBLIC_DOMAIN

    def test_restricted(self) -> None:
        assert classify_license("CC-BY-NC-4.0") == LicenseCategory.RESTRICTED

    def test_unknown(self) -> None:
        assert classify_license("") == LicenseCategory.UNKNOWN
        assert classify_license("CustomLicense") == LicenseCategory.UNKNOWN

    def test_case_insensitive_classification(self) -> None:
        # Classification falls through to pattern matching for unrecognized IDs
        assert classify_license("mit-style") == LicenseCategory.PERMISSIVE
        assert classify_license("gpl-like") == LicenseCategory.COPYLEFT


class TestCheckLicenseCompliance:
    """Tests for license compliance checking."""

    def test_compliant_by_default(self) -> None:
        info = LicenseInfo(spdx_id="MIT", category=LicenseCategory.PERMISSIVE)
        result = check_license_compliance(info)
        assert result.is_compliant is True

    def test_denied_license(self) -> None:
        info = LicenseInfo(spdx_id="GPL-3.0", category=LicenseCategory.COPYLEFT)
        result = check_license_compliance(info, denied_licenses=["GPL-3.0"])
        assert result.is_compliant is False
        assert "explicitly denied" in result.compliance_note

    def test_allowed_categories(self) -> None:
        info = LicenseInfo(spdx_id="GPL-3.0", category=LicenseCategory.COPYLEFT)
        result = check_license_compliance(
            info,
            allowed_categories=[LicenseCategory.PERMISSIVE],
        )
        assert result.is_compliant is False
        assert "not in allowed" in result.compliance_note

    def test_copyleft_allowed(self) -> None:
        info = LicenseInfo(spdx_id="GPL-3.0", category=LicenseCategory.COPYLEFT)
        result = check_license_compliance(
            info,
            allowed_categories=[LicenseCategory.PERMISSIVE, LicenseCategory.COPYLEFT],
        )
        assert result.is_compliant is True

    def test_unknown_license_non_compliant(self) -> None:
        info = LicenseInfo(spdx_id="", category=LicenseCategory.UNKNOWN)
        result = check_license_compliance(info)
        assert result.is_compliant is False
        assert "could not be determined" in result.compliance_note

    def test_no_allowed_categories_means_all_allowed(self) -> None:
        info = LicenseInfo(spdx_id="GPL-3.0", category=LicenseCategory.COPYLEFT)
        result = check_license_compliance(info, allowed_categories=None)
        assert result.is_compliant is True


class TestParseLicenseFromPyPI:
    """Tests for extracting license info from PyPI metadata."""

    def test_from_classifiers(self) -> None:
        """Test license extraction from Trove classifiers (most reliable)."""
        info = {
            "info": {
                "classifiers": [
                    "Development Status :: 5 - Production/Stable",
                    "License :: OSI Approved :: MIT License",
                    "Programming Language :: Python :: 3",
                ],
                "license": "MIT",
            }
        }
        result = parse_license_from_pypi(info)
        assert result.spdx_id == "MIT"
        assert result.category == LicenseCategory.PERMISSIVE

    def test_from_license_expression(self) -> None:
        """Test license extraction from PEP 639 license_expression."""
        info = {
            "info": {
                "classifiers": [],
                "license_expression": "Apache-2.0",
                "license": "Apache-2.0",
            }
        }
        result = parse_license_from_pypi(info)
        assert result.spdx_id == "Apache-2.0"
        assert result.category == LicenseCategory.PERMISSIVE

    def test_from_free_text_license(self) -> None:
        """Test fallback to info.license free text."""
        info = {
            "info": {
                "classifiers": [
                    "Programming Language :: Python :: 3",
                ],
                "license": "BSD-3-Clause",
            }
        }
        result = parse_license_from_pypi(info)
        assert result.spdx_id == "BSD-3-Clause"
        assert result.category == LicenseCategory.PERMISSIVE

    def test_unknown_license(self) -> None:
        """Test handling of packages with no license info."""
        info = {
            "info": {
                "classifiers": [],
                "license": "UNKNOWN",
            }
        }
        result = parse_license_from_pypi(info)
        assert result.spdx_id == ""
        assert result.category == LicenseCategory.UNKNOWN
        assert result.is_compliant is False

    def test_classifiers_preferred_over_free_text(self) -> None:
        """Classifiers should be preferred even when free text exists."""
        info = {
            "info": {
                "classifiers": [
                    "License :: OSI Approved :: Apache Software License",
                ],
                "license": "See LICENSE file",
            }
        }
        result = parse_license_from_pypi(info)
        assert result.spdx_id == "Apache-2.0"

    def test_copyleft_from_classifiers(self) -> None:
        """Test copyleft license detection from classifiers."""
        info = {
            "info": {
                "classifiers": [
                    "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
                ],
                "license": "GPLv3",
            }
        }
        result = parse_license_from_pypi(info)
        assert result.category == LicenseCategory.COPYLEFT

    def test_empty_info(self) -> None:
        """Test handling of empty info dict."""
        result = parse_license_from_pypi({"info": {}})
        assert result.spdx_id == ""
        assert result.category == LicenseCategory.UNKNOWN


class TestLicenseInfoToDict:
    """Tests for LicenseInfo serialization."""

    def test_to_dict(self) -> None:
        info = LicenseInfo(
            spdx_id="MIT",
            raw_license="MIT License",
            category=LicenseCategory.PERMISSIVE,
            is_compliant=True,
            compliance_note="",
        )
        d = info.to_dict()
        assert d["spdx_id"] == "MIT"
        assert d["category"] == "permissive"
        assert d["is_compliant"] is True

    def test_model_license_info_to_dict(self) -> None:
        """Test that models.LicenseInfo also serializes correctly."""
        info = ModelLicenseInfo(
            spdx_id="GPL-3.0",
            raw_license="GNU General Public License v3",
            category="copyleft",
            is_compliant=False,
            compliance_note="License category not in allowed",
        )
        d = info.to_dict()
        assert d["spdx_id"] == "GPL-3.0"
        assert d["category"] == "copyleft"
        assert d["is_compliant"] is False


class TestLicenseEdgeCases:
    """Tests for edge cases in license handling."""

    def test_semicolon_separated(self) -> None:
        result = normalize_license_id("MIT; BSD-3-Clause")
        assert result == "MIT"

    def test_quotes_stripped(self) -> None:
        result = normalize_license_id('"MIT"')
        assert result == "MIT"

    def test_see_license_text(self) -> None:
        """'SEE LICENSE' should result in empty/unknown."""
        result = normalize_license_id("SEE LICENSE")
        assert result == ""

    def test_noassertion_expression(self) -> None:
        """PEP 639 NOASSERTION should be treated as unknown."""
        info = {
            "info": {
                "classifiers": [],
                "license_expression": "NOASSERTION",
                "license": "Proprietary",
            }
        }
        result = parse_license_from_pypi(info)
        # Should fall through to free text
        assert result.spdx_id == "Proprietary"

    def test_multiple_classifiers(self) -> None:
        """Multiple license classifiers should use the first one found."""
        info = {
            "info": {
                "classifiers": [
                    "License :: OSI Approved :: MIT License",
                    "License :: OSI Approved :: BSD License",
                ],
                "license": "MIT",
            }
        }
        result = parse_license_from_pypi(info)
        # Should pick the first valid one
        assert result.category == LicenseCategory.PERMISSIVE
