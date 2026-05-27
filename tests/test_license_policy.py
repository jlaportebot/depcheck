"""Tests for LicensePolicy and ComplianceReport in depcheck.licenses."""

from __future__ import annotations

import pytest

from depcheck.licenses import (
    ComplianceReport,
    LicenseCategory,
    LicenseInfo,
    LicensePolicy,
    PackageComplianceEntry,
    render_compliance_json,
)

# ---------------------------------------------------------------------------
# LicensePolicy
# ---------------------------------------------------------------------------


class TestLicensePolicy:
    """Tests for LicensePolicy declarative allow/deny engine."""

    def test_default_policy_allows_all(self) -> None:
        policy = LicensePolicy()
        assert policy.check("MIT").is_compliant
        assert policy.check("GPL-3.0").is_compliant

    def test_denied_ids(self) -> None:
        policy = LicensePolicy(denied_ids={"GPL-3.0", "AGPL-3.0"})
        assert policy.check("MIT").is_compliant
        assert not policy.check("GPL-3.0").is_compliant
        assert "explicitly denied" in policy.check("GPL-3.0").reason

    def test_allowed_categories(self) -> None:
        policy = LicensePolicy(
            allowed_categories={LicenseCategory.PERMISSIVE, LicenseCategory.PUBLIC_DOMAIN}
        )
        assert policy.check("MIT").is_compliant
        assert policy.check("CC0-1.0").is_compliant
        result = policy.check("GPL-3.0")
        assert not result.is_compliant
        assert "not in allowed" in result.reason

    def test_denied_categories(self) -> None:
        policy = LicensePolicy(denied_categories={LicenseCategory.COPYLEFT})
        assert policy.check("MIT").is_compliant
        result = policy.check("GPL-3.0")
        assert not result.is_compliant
        assert "denied category" in result.reason

    def test_strict_mode_blocks_unknown(self) -> None:
        policy = LicensePolicy(default_allow=False)
        result = policy.check("")
        assert not result.is_compliant
        assert "strict mode" in result.reason

    def test_strict_mode_allows_known(self) -> None:
        policy = LicensePolicy(default_allow=False)
        assert policy.check("MIT").is_compliant

    def test_combined_allowed_and_denied(self) -> None:
        policy = LicensePolicy(
            allowed_categories={LicenseCategory.PERMISSIVE},
            denied_ids={"BSL-1.0"},
        )
        # MIT is permissive and not denied
        assert policy.check("MIT").is_compliant
        # BSL-1.0 is permissive but explicitly denied
        result = policy.check("BSL-1.0")
        assert not result.is_compliant
        assert "explicitly denied" in result.reason

    def test_empty_spdx_id_default_allow(self) -> None:
        policy = LicensePolicy(default_allow=True)
        assert policy.check("").is_compliant

    def test_empty_spdx_id_strict(self) -> None:
        policy = LicensePolicy(default_allow=False)
        assert not policy.check("").is_compliant

    def test_unknown_spdx_id_default_allow(self) -> None:
        policy = LicensePolicy(default_allow=True)
        assert policy.check("UNKNOWN").is_compliant

    def test_unknown_spdx_id_strict(self) -> None:
        policy = LicensePolicy(default_allow=False)
        assert not policy.check("UNKNOWN").is_compliant


# ---------------------------------------------------------------------------
# PackageComplianceEntry
# ---------------------------------------------------------------------------


class TestPackageComplianceEntry:
    """Tests for PackageComplianceEntry data model."""

    def test_to_dict_compliant(self) -> None:
        entry = PackageComplianceEntry(
            name="requests",
            version="2.31.0",
            license_info=LicenseInfo(spdx_id="Apache-2.0", category=LicenseCategory.PERMISSIVE),
            is_compliant=True,
        )
        d = entry.to_dict()
        assert d["name"] == "requests"
        assert d["is_compliant"] is True
        assert "denial_reason" not in d

    def test_to_dict_non_compliant(self) -> None:
        entry = PackageComplianceEntry(
            name="foobar",
            version="1.0",
            license_info=LicenseInfo(spdx_id="GPL-3.0", category=LicenseCategory.COPYLEFT),
            is_compliant=False,
            denial_reason="License category not in allowed",
        )
        d = entry.to_dict()
        assert d["is_compliant"] is False
        assert d["denial_reason"] == "License category not in allowed"


# ---------------------------------------------------------------------------
# ComplianceReport
# ---------------------------------------------------------------------------


class TestComplianceReport:
    """Tests for ComplianceReport data model."""

    def test_to_dict(self) -> None:
        report = ComplianceReport(
            packages=[
                PackageComplianceEntry(
                    name="a",
                    version="1.0",
                    license_info=LicenseInfo(spdx_id="MIT"),
                    is_compliant=True,
                ),
                PackageComplianceEntry(
                    name="b",
                    version="2.0",
                    license_info=LicenseInfo(spdx_id="GPL-3.0", category=LicenseCategory.COPYLEFT),
                    is_compliant=False,
                    denial_reason="Denied by policy",
                ),
            ],
            total=2,
            compliant_count=1,
            non_compliant_count=1,
            uncategorized_count=0,
        )
        d = report.to_dict()
        assert d["total"] == 2
        assert d["compliant"] == 1
        assert d["non_compliant"] == 1
        assert len(d["packages"]) == 2

    def test_empty_report(self) -> None:
        report = ComplianceReport()
        d = report.to_dict()
        assert d["total"] == 0
        assert d["packages"] == []


# ---------------------------------------------------------------------------
# render_compliance_json
# ---------------------------------------------------------------------------


class TestRenderComplianceJson:
    """Tests for render_compliance_json output."""

    def test_outputs_valid_json(self, capsys: pytest.CaptureFixture[str]) -> None:
        report = ComplianceReport(
            packages=[
                PackageComplianceEntry(
                    name="requests",
                    version="2.31.0",
                    license_info=LicenseInfo(spdx_id="Apache-2.0"),
                    is_compliant=True,
                ),
            ],
            total=1,
            compliant_count=1,
            non_compliant_count=0,
            uncategorized_count=0,
        )
        render_compliance_json(report)
        import json

        output = capsys.readouterr().out
        data = json.loads(output)
        assert data["total"] == 1
        assert data["compliant"] == 1
