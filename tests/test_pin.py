"""Tests for depcheck.pin — version pinning and integrity verification."""

from __future__ import annotations

import json
from pathlib import Path

from depcheck.pin import (
    IntegrityReport,
    IntegrityStatus,
    PinnedPackage,
    PinPolicy,
    PinPolicyConfig,
    PinPolicyRule,
    PinResult,
    Severity,
    read_pinfile,
    render_drift_json,
    render_drift_table,
    render_integrity_json,
    render_integrity_table,
    render_pin_json,
    render_pin_table,
    unpin_packages,
    write_pinfile,
)

# ---------------------------------------------------------------------------
# PinnedPackage tests
# ---------------------------------------------------------------------------


class TestPinnedPackage:
    def test_normalized_name(self):
        p = PinnedPackage(name="My_Package", version="1.0.0")
        assert p.normalized_name == "my-package"

    def test_pin_specifier_exact(self):
        p = PinnedPackage(name="foo", version="1.2.3", policy=PinPolicy.EXACT)
        assert p.pin_specifier == "==1.2.3"

    def test_pin_specifier_compatible(self):
        p = PinnedPackage(name="foo", version="1.2.3", policy=PinPolicy.COMPATIBLE)
        assert p.pin_specifier == "~=1.2"

    def test_pin_specifier_minimum(self):
        p = PinnedPackage(name="foo", version="1.2.3", policy=PinPolicy.MINIMUM)
        assert p.pin_specifier == ">=1.2.3"

    def test_pin_specifier_custom(self):
        p = PinnedPackage(
            name="foo", version="1.2.3", policy=PinPolicy.RANGE, specifier=">=1.2.3,<2.0.0"
        )
        assert p.pin_specifier == ">=1.2.3,<2.0.0"

    def test_has_hash_true(self):
        p = PinnedPackage(name="foo", version="1.0.0", hash_sha256="a" * 64)
        assert p.has_hash is True

    def test_has_hash_false(self):
        p = PinnedPackage(name="foo", version="1.0.0")
        assert p.has_hash is False

    def test_has_hash_md5(self):
        p = PinnedPackage(name="foo", version="1.0.0", hash_md5="b" * 32)
        assert p.has_hash is True

    def test_verify_hash_valid(self):
        import hashlib

        content = b"test content"
        sha = hashlib.sha256(content).hexdigest()
        p = PinnedPackage(name="foo", version="1.0.0", hash_sha256=sha)
        assert p.verify_hash(content) == IntegrityStatus.VALID

    def test_verify_hash_mismatch(self):
        import hashlib

        content = b"test content"
        _sha = hashlib.sha256(content).hexdigest()
        p = PinnedPackage(name="foo", version="1.0.0", hash_sha256="0" * 64)
        assert p.verify_hash(content) == IntegrityStatus.HASH_MISMATCH

    def test_verify_hash_not_pinned(self):
        p = PinnedPackage(name="foo", version="1.0.0")
        assert p.verify_hash(b"test") == IntegrityStatus.NOT_PINNED

    def test_verify_version_exact_match(self):
        p = PinnedPackage(name="foo", version="1.0.0", policy=PinPolicy.EXACT)
        assert p.verify_version("1.0.0") == IntegrityStatus.VALID

    def test_verify_version_exact_mismatch(self):
        p = PinnedPackage(name="foo", version="1.0.0", policy=PinPolicy.EXACT)
        assert p.verify_version("1.0.1") == IntegrityStatus.VERSION_MISMATCH

    def test_verify_version_minimum_match(self):
        p = PinnedPackage(name="foo", version="1.0.0", policy=PinPolicy.MINIMUM)
        assert p.verify_version("1.5.0") == IntegrityStatus.VALID

    def test_verify_version_minimum_below(self):
        p = PinnedPackage(name="foo", version="2.0.0", policy=PinPolicy.MINIMUM)
        assert p.verify_version("1.0.0") == IntegrityStatus.VERSION_MISMATCH

    def test_verify_version_yanked(self):
        p = PinnedPackage(name="foo", version="1.0.0", policy=PinPolicy.EXACT, yanked=True)
        assert p.verify_version("1.0.0") == IntegrityStatus.YANKED

    def test_verify_version_deprecated(self):
        p = PinnedPackage(
            name="foo",
            version="1.0.0",
            policy=PinPolicy.EXACT,
            deprecated=True,
            deprecation_message="Use bar instead",
        )
        assert p.verify_version("1.0.0") == IntegrityStatus.DEPRECATED

    def test_to_dict(self):
        p = PinnedPackage(
            name="foo",
            version="1.0.0",
            policy=PinPolicy.EXACT,
            hash_sha256="abc" + "0" * 61,
            source="pypi",
        )
        d = p.to_dict()
        assert d["name"] == "foo"
        assert d["version"] == "1.0.0"
        assert d["policy"] == "exact"


# ---------------------------------------------------------------------------
# PinPolicyRule tests
# ---------------------------------------------------------------------------


class TestPinPolicyRule:
    def test_matches_exact(self):
        rule = PinPolicyRule(pattern="requests", policy=PinPolicy.EXACT)
        assert rule.matches("requests") is True
        assert rule.matches("urllib3") is False

    def test_matches_wildcard(self):
        rule = PinPolicyRule(pattern="*", policy=PinPolicy.MINIMUM)
        assert rule.matches("anything") is True

    def test_matches_glob(self):
        rule = PinPolicyRule(pattern="django-*", policy=PinPolicy.COMPATIBLE)
        assert rule.matches("django-rest-framework") is True
        assert rule.matches("flask") is False

    def test_to_dict(self):
        rule = PinPolicyRule(pattern="*", policy=PinPolicy.EXACT, hash_required=True)
        d = rule.to_dict()
        assert d["pattern"] == "*"
        assert d["policy"] == "exact"


# ---------------------------------------------------------------------------
# PinPolicyConfig tests
# ---------------------------------------------------------------------------


class TestPinPolicyConfig:
    def test_default_policy(self):
        config = PinPolicyConfig()
        assert config.get_policy_for("anything") == PinPolicy.EXACT

    def test_custom_default(self):
        config = PinPolicyConfig(default_policy=PinPolicy.MINIMUM)
        assert config.get_policy_for("anything") == PinPolicy.MINIMUM

    def test_rule_overrides_default(self):
        config = PinPolicyConfig(
            default_policy=PinPolicy.EXACT,
            rules=[PinPolicyRule(pattern="django-*", policy=PinPolicy.COMPATIBLE)],
        )
        assert config.get_policy_for("django-rest-framework") == PinPolicy.COMPATIBLE
        assert config.get_policy_for("requests") == PinPolicy.EXACT

    def test_get_rule_for(self):
        rule = PinPolicyRule(pattern="flask", policy=PinPolicy.MINIMUM)
        config = PinPolicyConfig(rules=[rule])
        assert config.get_rule_for("flask") is rule
        assert config.get_rule_for("nonexistent") is None

    def test_to_dict(self):
        config = PinPolicyConfig(
            default_policy=PinPolicy.EXACT,
            require_hashes=True,
            fail_on_yanked=True,
        )
        d = config.to_dict()
        assert d["default_policy"] == "exact"
        assert d["require_hashes"] is True


# ---------------------------------------------------------------------------
# Pinfile I/O tests
# ---------------------------------------------------------------------------


class TestPinfileIO:
    def test_write_and_read_pinfile(self, tmp_path):
        pinned = [
            PinnedPackage(
                name="requests", version="2.31.0", policy=PinPolicy.EXACT, hash_sha256="a" * 64
            ),
            PinnedPackage(name="urllib3", version="2.0.7", policy=PinPolicy.EXACT),
        ]
        path = write_pinfile(pinned, project_path=str(tmp_path))
        assert Path(path).exists()

        read_back = read_pinfile(project_path=str(tmp_path))
        assert len(read_back) == 2
        names = {p.name for p in read_back}
        assert "requests" in names
        assert "urllib3" in names

    def test_read_nonexistent_pinfile(self, tmp_path):
        result = read_pinfile(project_path=str(tmp_path / "nonexistent"))
        assert result == []

    def test_write_empty_pinfile(self, tmp_path):
        path = write_pinfile([], project_path=str(tmp_path))
        assert Path(path).exists()
        read_back = read_pinfile(project_path=str(tmp_path))
        assert len(read_back) == 0

    def test_pinfile_presves_policy(self, tmp_path):
        pinned = [
            PinnedPackage(name="foo", version="1.0.0", policy=PinPolicy.COMPATIBLE),
            PinnedPackage(name="bar", version="2.0.0", policy=PinPolicy.MINIMUM),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))
        read_back = read_pinfile(project_path=str(tmp_path))
        policies = {p.name: p.policy for p in read_back}
        assert policies["foo"] == PinPolicy.COMPATIBLE
        assert policies["bar"] == PinPolicy.MINIMUM

    def test_pinfile_presves_extras(self, tmp_path):
        pinned = [
            PinnedPackage(name="requests", version="2.31.0", extras=["security", "socks"]),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))
        read_back = read_pinfile(project_path=str(tmp_path))
        pkg = next(p for p in read_back if p.name == "requests")
        assert pkg.extras == ["security", "socks"]


# ---------------------------------------------------------------------------
# IntegrityReport tests
# ---------------------------------------------------------------------------


class TestIntegrityReport:
    def test_total(self):
        from depcheck.pin import IntegrityCheckResult

        report = IntegrityReport(
            project_path=".",
            checks=[
                IntegrityCheckResult("a", "1.0", "1.0", IntegrityStatus.VALID, Severity.OK, "ok"),
                IntegrityCheckResult(
                    "b", "1.0", "2.0", IntegrityStatus.VERSION_MISMATCH, Severity.CRITICAL, "bad"
                ),
            ],
        )
        assert report.total == 2
        assert report.valid_count == 1
        assert report.mismatch_count == 1
        assert report.critical_count == 1

    def test_is_clean(self):
        from depcheck.pin import IntegrityCheckResult

        report = IntegrityReport(
            project_path=".",
            checks=[
                IntegrityCheckResult("a", "1.0", "1.0", IntegrityStatus.VALID, Severity.OK, "ok"),
            ],
        )
        assert report.is_clean

    def test_not_clean(self):
        from depcheck.pin import IntegrityCheckResult

        report = IntegrityReport(
            project_path=".",
            checks=[
                IntegrityCheckResult(
                    "a", "1.0", "2.0", IntegrityStatus.VERSION_MISMATCH, Severity.CRITICAL, "bad"
                ),
            ],
        )
        assert not report.is_clean

    def test_overall_severity_ok(self):
        from depcheck.pin import IntegrityCheckResult

        report = IntegrityReport(
            project_path=".",
            checks=[
                IntegrityCheckResult("a", "1.0", "1.0", IntegrityStatus.VALID, Severity.OK, "ok"),
            ],
        )
        assert report.overall_severity == Severity.OK

    def test_overall_severity_critical(self):
        from depcheck.pin import IntegrityCheckResult

        report = IntegrityReport(
            project_path=".",
            checks=[
                IntegrityCheckResult(
                    "a", "1.0", "2.0", IntegrityStatus.VERSION_MISMATCH, Severity.CRITICAL, "bad"
                ),
            ],
        )
        assert report.overall_severity == Severity.CRITICAL

    def test_to_dict(self):
        from depcheck.pin import IntegrityCheckResult

        report = IntegrityReport(
            project_path="/test",
            checks=[
                IntegrityCheckResult("a", "1.0", "1.0", IntegrityStatus.VALID, Severity.OK, "ok"),
                IntegrityCheckResult(
                    "b",
                    "2.0",
                    "1.0",
                    IntegrityStatus.VERSION_MISMATCH,
                    Severity.CRITICAL,
                    "mismatch",
                ),
            ],
        )
        d = report.to_dict()
        assert d["project_path"] == "/test"
        assert d["summary"]["total"] == 2
        assert d["summary"]["valid"] == 1
        assert d["summary"]["mismatches"] == 1


# ---------------------------------------------------------------------------
# IntegrityCheckResult tests
# ---------------------------------------------------------------------------


class TestIntegrityCheckResult:
    def test_to_dict(self):
        from depcheck.pin import IntegrityCheckResult

        check = IntegrityCheckResult(
            package="foo",
            installed_version="1.0.1",
            pinned_version="1.0.0",
            status=IntegrityStatus.VERSION_MISMATCH,
            severity=Severity.CRITICAL,
            message="Version mismatch",
            fix_suggestion="Reinstall",
        )
        d = check.to_dict()
        assert d["package"] == "foo"
        assert d["status"] == "version_mismatch"
        assert d["severity"] == "critical"


# ---------------------------------------------------------------------------
# PinResult tests
# ---------------------------------------------------------------------------


class TestPinResult:
    def test_total_pinned(self):
        result = PinResult(
            pinned=[
                PinnedPackage(name="a", version="1.0"),
                PinnedPackage(name="b", version="2.0"),
            ]
        )
        assert result.total_pinned == 2

    def test_to_dict(self):
        result = PinResult(
            pinned=[PinnedPackage(name="a", version="1.0")],
            skipped=["c"],
            errors=["error msg"],
            lockfile_path="/tmp/pin.json",
        )
        d = result.to_dict()
        assert d["total_pinned"] == 1
        assert "c" in d["skipped"]


# ---------------------------------------------------------------------------
# Rendering tests
# ---------------------------------------------------------------------------


class TestPinRendering:
    def test_render_pin_table(self):
        from io import StringIO

        from rich.console import Console

        result = PinResult(
            pinned=[
                PinnedPackage(
                    name="requests", version="2.31.0", policy=PinPolicy.EXACT, hash_sha256="a" * 64
                ),
                PinnedPackage(name="flask", version="3.0.0", policy=PinPolicy.MINIMUM),
            ],
            lockfile_path="/tmp/pin.json",
        )
        console = Console(file=StringIO(), width=200)
        render_pin_table(result, console=console)
        output = console.file.getvalue()
        assert "Pinned 2 packages" in output

    def test_render_integrity_table(self):
        from io import StringIO

        from rich.console import Console

        from depcheck.pin import IntegrityCheckResult

        report = IntegrityReport(
            project_path="/test",
            checks=[
                IntegrityCheckResult("a", "1.0", "1.0", IntegrityStatus.VALID, Severity.OK, "ok"),
                IntegrityCheckResult(
                    "b",
                    "2.0",
                    "1.0",
                    IntegrityStatus.VERSION_MISMATCH,
                    Severity.CRITICAL,
                    "mismatch",
                ),
            ],
        )
        console = Console(file=StringIO(), width=200)
        render_integrity_table(report, console=console)
        output = console.file.getvalue()
        assert "Integrity Verification" in output

    def test_render_drift_table(self):
        from io import StringIO

        from rich.console import Console

        from depcheck.pin import PinDrift

        _report = IntegrityReport(project_path=".")
        from depcheck.pin import PinDriftReport

        drift_report = PinDriftReport(
            drifts=[
                PinDrift(
                    package="requests",
                    pinned_version="2.28.0",
                    latest_version="2.31.0",
                    drift_type="minor",
                ),
                PinDrift(
                    package="flask",
                    pinned_version="2.0.0",
                    latest_version="3.0.0",
                    drift_type="major",
                ),
            ],
            up_to_date_count=5,
            total_pinned=7,
        )
        console = Console(file=StringIO(), width=200)
        render_drift_table(drift_report, console=console)
        output = console.file.getvalue()
        assert "Pin Drift Report" in output

    def test_render_pin_json(self):
        result = PinResult(pinned=[PinnedPackage(name="foo", version="1.0.0")])
        json_str = render_pin_json(result)
        data = json.loads(json_str)
        assert data["total_pinned"] == 1

    def test_render_integrity_json(self):
        from depcheck.pin import IntegrityCheckResult

        report = IntegrityReport(
            project_path="/test",
            checks=[
                IntegrityCheckResult("a", "1.0", "1.0", IntegrityStatus.VALID, Severity.OK, "ok"),
            ],
        )
        json_str = render_integrity_json(report)
        data = json.loads(json_str)
        assert data["summary"]["total"] == 1

    def test_render_drift_json(self):
        from depcheck.pin import PinDrift, PinDriftReport

        report = PinDriftReport(
            drifts=[
                PinDrift(
                    package="foo", pinned_version="1.0", latest_version="2.0", drift_type="major"
                )
            ],
            total_pinned=5,
        )
        json_str = render_drift_json(report)
        data = json.loads(json_str)
        assert data["summary"]["major"] == 1


# ---------------------------------------------------------------------------
# Pin drift tests
# ---------------------------------------------------------------------------


class TestPinDrift:
    def test_drift_is_significant_major(self):
        from depcheck.pin import PinDrift

        drift = PinDrift(
            package="foo", pinned_version="1.0", latest_version="2.0", drift_type="major"
        )
        assert drift.is_significant is True

    def test_drift_is_not_significant_patch(self):
        from depcheck.pin import PinDrift

        drift = PinDrift(
            package="foo", pinned_version="1.0.0", latest_version="1.0.1", drift_type="patch"
        )
        assert drift.is_significant is False

    def test_drift_is_significant_security(self):
        from depcheck.pin import PinDrift

        drift = PinDrift(
            package="foo",
            pinned_version="1.0.0",
            latest_version="1.0.1",
            drift_type="patch",
            is_security_update=True,
        )
        assert drift.is_significant is True

    def test_drift_to_dict(self):
        from depcheck.pin import PinDrift

        drift = PinDrift(
            package="foo",
            pinned_version="1.0",
            latest_version="2.0",
            drift_type="major",
            is_security_update=True,
        )
        d = drift.to_dict()
        assert d["package"] == "foo"
        assert d["is_significant"] is True


class TestPinDriftReport:
    def test_significant_drifts(self):
        from depcheck.pin import PinDrift, PinDriftReport

        report = PinDriftReport(
            drifts=[
                PinDrift(
                    package="a", pinned_version="1.0", latest_version="2.0", drift_type="major"
                ),
                PinDrift(
                    package="b", pinned_version="1.0.0", latest_version="1.0.1", drift_type="patch"
                ),
                PinDrift(
                    package="c", pinned_version="1.0", latest_version="1.1", drift_type="minor"
                ),
            ]
        )
        assert len(report.significant_drifts) == 2  # major + minor

    def test_security_drifts(self):
        from depcheck.pin import PinDrift, PinDriftReport

        report = PinDriftReport(
            drifts=[
                PinDrift(
                    package="a",
                    pinned_version="1.0",
                    latest_version="2.0",
                    drift_type="major",
                    is_security_update=True,
                ),
                PinDrift(
                    package="b", pinned_version="1.0", latest_version="1.1", drift_type="minor"
                ),
            ]
        )
        assert len(report.security_drifts) == 1

    def test_to_dict(self):
        from depcheck.pin import PinDrift, PinDriftReport

        report = PinDriftReport(
            drifts=[
                PinDrift(
                    package="a", pinned_version="1.0", latest_version="2.0", drift_type="major"
                )
            ],
            total_pinned=5,
            up_to_date_count=4,
        )
        d = report.to_dict()
        assert d["total_pinned"] == 5
        assert d["summary"]["major"] == 1


# ---------------------------------------------------------------------------
# Pin operations with mocking
# ---------------------------------------------------------------------------


class TestPinOperations:
    def test_unpin_packages(self, tmp_path):
        """Test unpinning specific packages."""
        pinned = [
            PinnedPackage(name="requests", version="2.31.0"),
            PinnedPackage(name="urllib3", version="2.0.7"),
            PinnedPackage(name="flask", version="3.0.0"),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))

        removed = unpin_packages(str(tmp_path), ["urllib3"])
        assert "urllib3" in removed

        remaining = read_pinfile(project_path=str(tmp_path))
        assert len(remaining) == 2
        names = {p.name for p in remaining}
        assert "requests" in names
        assert "flask" in names

    def test_unpin_all_packages_removes_file(self, tmp_path):
        """If all packages are unpinned, the pinfile should be removed."""
        pinned = [PinnedPackage(name="requests", version="2.31.0")]
        write_pinfile(pinned, project_path=str(tmp_path))

        removed = unpin_packages(str(tmp_path), ["requests"])
        assert "requests" in removed
        assert not (tmp_path / "depcheck.pin.json").exists()

    def test_unpin_nonexistent_package(self, tmp_path):
        """Unpinning a package that doesn't exist should be a no-op."""
        pinned = [PinnedPackage(name="requests", version="2.31.0")]
        write_pinfile(pinned, project_path=str(tmp_path))

        removed = unpin_packages(str(tmp_path), ["nonexistent"])
        assert removed == []

        remaining = read_pinfile(project_path=str(tmp_path))
        assert len(remaining) == 1


# ---------------------------------------------------------------------------
# PinPolicyConfig advanced tests
# ---------------------------------------------------------------------------


class TestPinPolicyConfigAdvanced:
    def test_multiple_rules(self):
        rules = [
            PinPolicyRule(pattern="django-*", policy=PinPolicy.COMPATIBLE),
            PinPolicyRule(pattern="requests", policy=PinPolicy.MINIMUM),
            PinPolicyRule(pattern="*", policy=PinPolicy.EXACT),
        ]
        config = PinPolicyConfig(default_policy=PinPolicy.EXACT, rules=rules)
        assert config.get_policy_for("django-rest-framework") == PinPolicy.COMPATIBLE
        assert config.get_policy_for("requests") == PinPolicy.MINIMUM
        assert config.get_policy_for("flask") == PinPolicy.EXACT

    def test_case_insensitive_match(self):
        rule = PinPolicyRule(pattern="Requests", policy=PinPolicy.MINIMUM)
        assert rule.matches("requests") is True


# ---------------------------------------------------------------------------
# PinnedPackage verify_hash with multiple algorithms
# ---------------------------------------------------------------------------


class TestPinnedPackageHashVerification:
    def test_verify_sha256_valid(self):
        import hashlib

        content = b"hello world"
        sha = hashlib.sha256(content).hexdigest()
        p = PinnedPackage(name="pkg", version="1.0", hash_sha256=sha)
        assert p.verify_hash(content) == IntegrityStatus.VALID

    def test_verify_md5_valid(self):
        import hashlib

        content = b"hello world"
        md5 = hashlib.md5(content).hexdigest()
        p = PinnedPackage(name="pkg", version="1.0", hash_md5=md5)
        assert p.verify_hash(content) == IntegrityStatus.VALID

    def test_verify_blake2b_valid(self):
        import hashlib

        content = b"hello world"
        blake = hashlib.blake2b(content, digest_size=32).hexdigest()
        p = PinnedPackage(name="pkg", version="1.0", hash_blake2b=blake)
        assert p.verify_hash(content) == IntegrityStatus.VALID

    def test_verify_sha256_mismatch(self):
        p = PinnedPackage(name="pkg", version="1.0", hash_sha256="0" * 64)
        assert p.verify_hash(b"test") == IntegrityStatus.HASH_MISMATCH

    def test_verify_multiple_hashes_first_fails(self):
        import hashlib

        content = b"hello"
        md5 = hashlib.md5(content).hexdigest()
        p = PinnedPackage(name="pkg", version="1.0", hash_sha256="wrong", hash_md5=md5)
        # SHA-256 mismatch is checked first
        assert p.verify_hash(content) == IntegrityStatus.HASH_MISMATCH


# ---------------------------------------------------------------------------
# Integration: full pin → verify workflow
# ---------------------------------------------------------------------------


class TestPinVerifyWorkflow:
    def test_write_read_verify_cycle(self, tmp_path):
        """Write a pinfile, read it, and verify all packages have correct data."""
        pinned = [
            PinnedPackage(
                name="requests",
                version="2.31.0",
                policy=PinPolicy.EXACT,
                hash_sha256="a" * 64,
                pinned_at="2024-01-01T00:00:00Z",
            ),
            PinnedPackage(
                name="flask",
                version="3.0.0",
                policy=PinPolicy.COMPATIBLE,
            ),
        ]
        path = write_pinfile(pinned, project_path=str(tmp_path))
        assert Path(path).exists()

        read_back = read_pinfile(project_path=str(tmp_path))
        assert len(read_back) == 2

        for orig, read in zip(
            sorted(pinned, key=lambda p: p.name), sorted(read_back, key=lambda p: p.name)
        ):
            assert orig.name == read.name
            assert orig.version == read.version
            assert orig.policy == read.policy

    def test_pinfile_json_structure(self, tmp_path):
        """Verify the pinfile JSON has the expected structure."""
        pinned = [PinnedPackage(name="foo", version="1.0.0")]
        path = write_pinfile(pinned, project_path=str(tmp_path))
        data = json.loads(Path(path).read_text())
        assert "$schema" in data
        assert "pinfileVersion" in data
        assert "packages" in data
        assert "foo" in data["packages"]

    def test_unpin_preserves_other_packages(self, tmp_path):
        """Unpin one package, ensure others are preserved with their data."""
        pinned = [
            PinnedPackage(name="a", version="1.0.0", hash_sha256="a" * 64),
            PinnedPackage(name="b", version="2.0.0", hash_sha256="b" * 64),
            PinnedPackage(name="c", version="3.0.0", hash_sha256="c" * 64),
        ]
        write_pinfile(pinned, project_path=str(tmp_path))
        unpin_packages(str(tmp_path), ["b"])

        remaining = read_pinfile(project_path=str(tmp_path))
        assert len(remaining) == 2
        names = {p.name for p in remaining}
        assert names == {"a", "c"}
        # Verify hash is preserved
        for pkg in remaining:
            if pkg.name == "a":
                assert pkg.hash_sha256 == "a" * 64


# ---------------------------------------------------------------------------
# Edge case tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_pinfile_roundtrip(self, tmp_path):
        write_pinfile([], project_path=str(tmp_path))
        read_back = read_pinfile(project_path=str(tmp_path))
        assert read_back == []

    def test_invalid_json_pinfile(self, tmp_path):
        """Reading an invalid JSON pinfile should return empty list."""
        pinfile = tmp_path / "depcheck.pin.json"
        pinfile.write_text("not valid json{{{")
        result = read_pinfile(project_path=str(tmp_path))
        assert result == []

    def test_pin_result_empty(self):
        result = PinResult()
        assert result.total_pinned == 0

    def test_integrity_report_empty(self):
        report = IntegrityReport(project_path=".")
        assert report.total == 0
        assert report.overall_severity == Severity.OK

    def test_verify_version_with_invalid_installed_version(self):
        p = PinnedPackage(name="foo", version="1.0.0", policy=PinPolicy.EXACT)
        # Invalid version should still compare as string for EXACT
        assert p.verify_version("not-a-version") == IntegrityStatus.VERSION_MISMATCH

    def test_compatible_pin_with_single_version_part(self):
        p = PinnedPackage(name="foo", version="1", policy=PinPolicy.COMPATIBLE)
        # Single part version → ~=1
        assert p.pin_specifier == "~=1"

    def test_pinned_package_is_editable(self):
        p = PinnedPackage(name="my-pkg", version="0.0.0", is_editable=True)
        assert p.is_editable is True

    def test_pinned_package_is_vcs(self):
        p = PinnedPackage(
            name="my-pkg",
            version="0.0.0",
            is_vcs=True,
            vcs_url="git+https://github.com/org/repo.git",
        )
        assert p.is_vcs is True
        assert p.vcs_url.startswith("git+")
