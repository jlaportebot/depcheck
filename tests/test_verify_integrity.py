"""Integration tests for verify_integrity function."""

from __future__ import annotations

import pytest

from depcheck.pin import (
    IntegrityReport,
    IntegrityStatus,
    PinnedPackage,
    PinPolicy,
    Severity,
    verify_integrity,
    write_pinfile,
)


class TestVerifyIntegrityIntegration:
    """Integration tests for verify_integrity function."""

    def test_verify_integrity_all_valid(self, tmp_path, monkeypatch):
        """Test verify_integrity when all packages match."""
        # Create a pinfile with exact versions
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", policy=PinPolicy.EXACT),
            PinnedPackage(name="urllib3", version="2.0.7", policy=PinPolicy.EXACT),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        # Mock scan_project to return matching versions
        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.31.0", is_yanked=False),
                    PackageReport(name="urllib3", installed_version="2.0.7", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert isinstance(report, IntegrityReport)
        assert report.total == 2
        assert report.valid_count == 2
        assert report.mismatch_count == 0
        assert report.critical_count == 0
        assert report.overall_severity == Severity.OK
        assert report.is_clean

        for check in report.checks:
            assert check.status == IntegrityStatus.VALID
            assert check.severity == Severity.OK

    def test_verify_integrity_version_mismatch(self, tmp_path, monkeypatch):
        """Test verify_integrity detects version mismatch."""
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", policy=PinPolicy.EXACT),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.30.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 1
        assert report.valid_count == 0
        assert report.mismatch_count == 1
        assert report.critical_count == 1
        assert report.overall_severity == Severity.CRITICAL
        assert not report.is_clean

        check = report.checks[0]
        assert check.status == IntegrityStatus.VERSION_MISMATCH
        assert check.severity == Severity.CRITICAL
        assert "Version mismatch" in check.message
        assert check.fix_suggestion == "Reinstall: pip install requests==2.31.0"

    def test_verify_integrity_missing_package(self, tmp_path, monkeypatch):
        """Test verify_integrity detects missing package."""
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", policy=PinPolicy.EXACT),
            PinnedPackage(name="missing-package", version="1.0.0", policy=PinPolicy.EXACT),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.31.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 2
        assert report.valid_count == 1
        assert report.critical_count == 1
        assert report.overall_severity == Severity.CRITICAL

        # Find the missing package check
        missing_check = next(c for c in report.checks if c.package == "missing-package")
        assert missing_check.status == IntegrityStatus.MISSING
        assert missing_check.severity == Severity.CRITICAL
        assert "is pinned but not installed" in missing_check.message
        assert "pip install missing-package==1.0.0" in missing_check.fix_suggestion

    def test_verify_integrity_yanked_package(self, tmp_path, monkeypatch):
        """Test verify_integrity detects yanked package."""
        pinned = [
            PinnedPackage(
                name="yanked-pkg",
                version="1.0.0",
                policy=PinPolicy.EXACT,
                yanked=True,
                yanked_reason="Security vulnerability",
            ),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="yanked-pkg", installed_version="1.0.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 1
        assert report.critical_count == 1
        assert report.overall_severity == Severity.CRITICAL

        check = report.checks[0]
        assert check.status == IntegrityStatus.YANKED
        assert check.severity == Severity.CRITICAL
        assert "has been yanked" in check.message
        # yanked_reason not persisted in pinfile, so message ends with colon
        assert check.message.endswith(": ")
        assert "depcheck pin --update yanked-pkg" in check.fix_suggestion

    def test_verify_integrity_deprecated_package(self, tmp_path, monkeypatch):
        """Test verify_integrity detects deprecated package."""
        pinned = [
            PinnedPackage(
                name="deprecated-pkg",
                version="1.0.0",
                policy=PinPolicy.EXACT,
                deprecated=True,
                deprecation_message="Use new-pkg instead",
            ),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(
                        name="deprecated-pkg",
                        installed_version="1.0.0",
                        is_yanked=False,
                    ),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 1
        assert report.warning_count == 1
        assert report.overall_severity == Severity.WARNING

        check = report.checks[0]
        assert check.status == IntegrityStatus.DEPRECATED
        assert check.severity == Severity.WARNING
        assert "is deprecated" in check.message
        assert "Use new-pkg instead" in check.message
        assert "Consider migrating to a maintained alternative" in check.fix_suggestion

    def test_verify_integrity_malformed_hash(self, tmp_path, monkeypatch):
        """Test verify_integrity detects malformed SHA-256 hash."""
        pinned = [
            PinnedPackage(
                name="requests",
                version="2.31.0",
                policy=PinPolicy.EXACT,
                hash_sha256="not-a-valid-hash",
            ),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.31.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 1
        assert report.warning_count == 1
        assert report.overall_severity == Severity.WARNING

        check = report.checks[0]
        assert check.status == IntegrityStatus.HASH_MISMATCH
        assert check.severity == Severity.WARNING
        assert "appears malformed" in check.message
        assert check.expected_hash == "not-a-valid-hash"
        assert "Re-pin the package" in check.fix_suggestion

    def test_verify_integrity_compatible_policy(self, tmp_path, monkeypatch):
        """Test verify_integrity with COMPATIBLE pin policy."""
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", policy=PinPolicy.COMPATIBLE),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.31.5", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 1
        assert report.valid_count == 1
        assert report.overall_severity == Severity.OK

        check = report.checks[0]
        assert check.status == IntegrityStatus.VALID

    def test_verify_integrity_compatible_policy_mismatch(self, tmp_path, monkeypatch):
        """Test verify_integrity with COMPATIBLE pin policy mismatch."""
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", policy=PinPolicy.COMPATIBLE),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="3.0.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 1
        assert report.critical_count == 1
        assert report.overall_severity == Severity.CRITICAL

        check = report.checks[0]
        assert check.status == IntegrityStatus.VERSION_MISMATCH

    def test_verify_integrity_minimum_policy(self, tmp_path, monkeypatch):
        """Test verify_integrity with MINIMUM pin policy."""
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", policy=PinPolicy.MINIMUM),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.32.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 1
        assert report.valid_count == 1
        assert report.overall_severity == Severity.OK

    def test_verify_integrity_minimum_policy_below(self, tmp_path, monkeypatch):
        """Test verify_integrity with MINIMUM pin policy below minimum."""
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", policy=PinPolicy.MINIMUM),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.30.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 1
        assert report.critical_count == 1
        assert report.overall_severity == Severity.CRITICAL

    def test_verify_integrity_mixed_results(self, tmp_path, monkeypatch):
        """Test verify_integrity with mixed valid, mismatch, missing, yanked, deprecated."""
        pinned = [
            PinnedPackage(name="valid-pkg", version="1.0.0", policy=PinPolicy.EXACT),
            PinnedPackage(name="mismatch-pkg", version="2.0.0", policy=PinPolicy.EXACT),
            PinnedPackage(name="missing-pkg", version="3.0.0", policy=PinPolicy.EXACT),
            PinnedPackage(name="yanked-pkg", version="4.0.0", policy=PinPolicy.EXACT, yanked=True),
            PinnedPackage(
                name="deprecated-pkg",
                version="5.0.0",
                policy=PinPolicy.EXACT,
                deprecated=True,
                deprecation_message="Use something else",
            ),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="valid-pkg", installed_version="1.0.0", is_yanked=False),
                    PackageReport(
                        name="mismatch-pkg",
                        installed_version="2.1.0",
                        is_yanked=False,
                    ),
                    PackageReport(
                        name="yanked-pkg",
                        installed_version="4.0.0",
                        is_yanked=False,
                    ),
                    PackageReport(
                        name="deprecated-pkg",
                        installed_version="5.0.0",
                        is_yanked=False,
                    ),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 5
        assert report.valid_count == 1
        assert report.mismatch_count == 1
        assert report.critical_count == 3  # mismatch + yanked + missing
        assert report.warning_count == 1  # deprecated
        assert report.overall_severity == Severity.CRITICAL
        assert not report.is_clean

        # Verify each check
        statuses = {c.package: c.status for c in report.checks}
        assert statuses["valid-pkg"] == IntegrityStatus.VALID
        assert statuses["mismatch-pkg"] == IntegrityStatus.VERSION_MISMATCH
        assert statuses["missing-pkg"] == IntegrityStatus.MISSING
        assert statuses["yanked-pkg"] == IntegrityStatus.YANKED
        assert statuses["deprecated-pkg"] == IntegrityStatus.DEPRECATED

    def test_verify_integrity_no_pinfile(self, tmp_path):
        """Test verify_integrity when no pinfile exists."""
        report = verify_integrity(project_path=str(tmp_path))

        assert report.total == 0
        assert len(report.errors) == 1
        assert "No pinfile found" in report.errors[0]

    def test_verify_integrity_skip_hash_check(self, tmp_path, monkeypatch):
        """Test verify_integrity with check_hashes=False."""
        pinned = [
            PinnedPackage(
                name="requests",
                version="2.31.0",
                policy=PinPolicy.EXACT,
                hash_sha256="not-a-valid-hash",
            ),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.31.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        # With hash check disabled, should pass
        report = verify_integrity(project_path=str(tmp_path), check_hashes=False)

        assert report.total == 1
        assert report.valid_count == 1
        assert report.overall_severity == Severity.OK

    def test_verify_integrity_skip_version_check(self, tmp_path, monkeypatch):
        """Test verify_integrity with check_versions=False."""
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", policy=PinPolicy.EXACT),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="requests", installed_version="2.30.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        # With version check disabled, should pass
        report = verify_integrity(project_path=str(tmp_path), check_versions=False)

        assert report.total == 1
        assert report.valid_count == 1
        assert report.overall_severity == Severity.OK

    def test_verify_integrity_skip_yanked_check(self, tmp_path, monkeypatch):
        """Test verify_integrity with check_yanked=False."""
        pinned = [
            PinnedPackage(
                name="yanked-pkg",
                version="1.0.0",
                policy=PinPolicy.EXACT,
                yanked=True,
                yanked_reason="Security issue",
            ),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(name="yanked-pkg", installed_version="1.0.0", is_yanked=False),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        # With yanked check disabled, should pass
        report = verify_integrity(project_path=str(tmp_path), check_yanked=False)

        assert report.total == 1
        assert report.valid_count == 1
        assert report.overall_severity == Severity.OK

    def test_verify_integrity_skip_deprecated_check(self, tmp_path, monkeypatch):
        """Test verify_integrity with check_deprecated=False."""
        pinned = [
            PinnedPackage(
                name="deprecated-pkg",
                version="1.0.0",
                policy=PinPolicy.EXACT,
                deprecated=True,
                deprecation_message="Use new-pkg",
            ),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        def mock_scan_project(project_path, check_vulnerabilities, check_licenses):
            from depcheck.models import PackageReport, ScanResult

            return ScanResult(
                project_path=project_path,
                packages=[
                    PackageReport(
                        name="deprecated-pkg",
                        installed_version="1.0.0",
                        is_yanked=False,
                    ),
                ],
                errors=[],
            )

        monkeypatch.setattr("depcheck.scanner.scan_project", mock_scan_project)

        # With deprecated check disabled, should pass
        report = verify_integrity(project_path=str(tmp_path), check_deprecated=False)

        assert report.total == 1
        assert report.valid_count == 1
        assert report.overall_severity == Severity.OK


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
