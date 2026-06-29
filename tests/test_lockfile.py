"""Tests for the depcheck.lockfile module — lockfile analysis."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from depcheck.lockfile import (
    DriftEntry,
    HashMismatch,
    LockedPackage,
    LockfileDiff,
    LockfileReport,
    ManifestRequirement,
    PipAuditResult,
    UnpinnedDependency,
    analyze_drift,
    analyze_hashes,
    analyze_lockfile,
    analyze_unpinned,
    detect_lockfile_type,
    diff_lockfiles,
    find_lockfiles,
    parse_pip_freeze,
    parse_pipfile_lock,
    parse_poetry_lock,
    parse_requirements_txt,
    render_lockfile_json,
    render_lockfile_table,
    run_pip_audit,
)

# ---------------------------------------------------------------------------
# Detect lockfile type
# ---------------------------------------------------------------------------


class TestDetectLockfileType:
    """Tests for detect_lockfile_type."""

    def test_pipfile_lock(self, tmp_path):
        f = tmp_path / "Pipfile.lock"
        f.write_text("{}")
        assert detect_lockfile_type(f) == "pipfile_lock"

    def test_poetry_lock(self, tmp_path):
        f = tmp_path / "poetry.lock"
        f.write_text('[[package]]\nname = "foo"\nversion = "1.0.0"')
        assert detect_lockfile_type(f) == "poetry_lock"

    def test_requirements_txt(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("click==8.0.0\nrich==13.0.0\n")
        assert detect_lockfile_type(f) == "requirements_txt"

    def test_pip_freeze_format(self, tmp_path):
        f = tmp_path / "freeze.txt"
        f.write_text("click==8.0.0\nrich==13.0.0\nhttpx==0.24.0\n")
        assert detect_lockfile_type(f) == "pip_freeze"

    def test_requirements_lock(self, tmp_path):
        f = tmp_path / "requirements.lock"
        f.write_text("click==8.0.0\n")
        assert detect_lockfile_type(f) == "requirements_txt"


# ---------------------------------------------------------------------------
# Parse pip freeze
# ---------------------------------------------------------------------------


class TestParsePipFreeze:
    """Tests for parse_pip_freeze."""

    def test_basic_freeze(self):
        content = "click==8.0.0\nrich==13.0.0\nhttpx==0.24.0\n"
        packages = parse_pip_freeze(content)
        assert len(packages) == 3
        assert packages[0].name == "click"
        assert packages[0].version == "8.0.0"
        assert packages[1].name == "rich"
        assert packages[2].version == "0.24.0"

    def test_freeze_with_comments(self):
        content = "# This is a comment\nclick==8.0.0\n# Another comment\nrich==13.0.0\n"
        packages = parse_pip_freeze(content)
        assert len(packages) == 2

    def test_freeze_skips_editable(self):
        content = "click==8.0.0\n-e git+https://github.com/user/repo.git#egg=repo\nrich==13.0.0\n"
        packages = parse_pip_freeze(content)
        assert len(packages) == 2
        assert all(p.name != "repo" for p in packages)

    def test_freeze_empty(self):
        packages = parse_pip_freeze("")
        assert len(packages) == 0

    def test_freeze_non_match(self):
        content = "some-random-line\nanother-bad-line\n"
        packages = parse_pip_freeze(content)
        assert len(packages) == 0


# ---------------------------------------------------------------------------
# Parse requirements.txt
# ---------------------------------------------------------------------------


class TestParseRequirementsTxt:
    """Tests for parse_requirements_txt."""

    def test_pinned_requirement(self):
        content = "click==8.0.0\n"
        packages, reqs = parse_requirements_txt(content)
        assert len(reqs) == 1
        assert reqs[0].name == "click"
        assert reqs[0].is_pinned is True
        assert reqs[0].specifier == "==8.0.0"

    def test_unpinned_requirement(self):
        content = "requests\n"
        packages, reqs = parse_requirements_txt(content)
        assert len(reqs) == 1
        assert reqs[0].name == "requests"
        assert reqs[0].is_pinned is False
        assert reqs[0].specifier == ""

    def test_range_requirement(self):
        content = "django>=4.0,<5.0\n"
        packages, reqs = parse_requirements_txt(content)
        assert len(reqs) == 1
        assert reqs[0].name == "django"
        assert reqs[0].is_pinned is False
        assert ">=4.0" in reqs[0].specifier

    def test_with_extras(self):
        content = "requests[security]==2.28.0\n"
        packages, reqs = parse_requirements_txt(content)
        assert len(reqs) == 1
        assert reqs[0].name == "requests"
        assert "security" in reqs[0].extras
        assert reqs[0].is_pinned is True

    def test_with_markers(self):
        content = 'tomli>=2.0; python_version < "3.11"\n'
        packages, reqs = parse_requirements_txt(content)
        assert len(reqs) == 1
        assert 'python_version < "3.11"' in reqs[0].markers

    def test_with_hashes(self):
        content = "click==8.0.0 --hash=sha256:abc123\n"
        packages, reqs = parse_requirements_txt(content)
        assert len(packages) == 1
        assert len(packages[0].hashes) == 1
        assert "sha256:abc123" in packages[0].hashes
        assert reqs[0].has_hash is True

    def test_comments_and_options(self):
        content = "# This is a comment\n--index-url https://pypi.org/simple\nclick==8.0.0\n"
        packages, reqs = parse_requirements_txt(content)
        assert len(reqs) == 1
        assert reqs[0].name == "click"

    def test_empty_lines(self):
        content = "click==8.0.0\n\nrich==13.0.0\n\n"
        packages, reqs = parse_requirements_txt(content)
        assert len(reqs) == 2


# ---------------------------------------------------------------------------
# Parse Pipfile.lock
# ---------------------------------------------------------------------------


class TestParsePipfileLock:
    """Tests for parse_pipfile_lock."""

    def test_basic_pipfile_lock(self):
        content = json.dumps(
            {
                "default": {
                    "requests": {
                        "version": "==2.28.0",
                        "hashes": ["sha256:abc123"],
                    },
                    "click": {
                        "version": "==8.0.0",
                        "hashes": ["sha256:def456"],
                    },
                },
                "develop": {
                    "pytest": {
                        "version": "==7.0.0",
                        "hashes": [],
                    },
                },
            }
        )
        packages = parse_pipfile_lock(content)
        assert len(packages) == 3
        names = {p.name for p in packages}
        assert "requests" in names
        assert "click" in names
        assert "pytest" in names

    def test_invalid_json(self):
        packages = parse_pipfile_lock("not json")
        assert len(packages) == 0

    def test_empty_pipfile_lock(self):
        packages = parse_pipfile_lock("{}")
        assert len(packages) == 0


# ---------------------------------------------------------------------------
# Parse poetry.lock
# ---------------------------------------------------------------------------


class TestParsePoetryLock:
    """Tests for parse_poetry_lock."""

    def test_basic_poetry_lock(self):
        content = """[[package]]
name = "requests"
version = "2.28.0"

[[package]]
name = "click"
version = "8.0.0"

[metadata]
format-version = "2.0"
"""
        packages = parse_poetry_lock(content)
        assert len(packages) == 2
        assert packages[0].name == "requests"
        assert packages[0].version == "2.28.0"
        assert packages[1].name == "click"

    def test_single_package(self):
        content = '[[package]]\nname = "flask"\nversion = "2.0.0"\n'
        packages = parse_poetry_lock(content)
        assert len(packages) == 1
        assert packages[0].name == "flask"


# ---------------------------------------------------------------------------
# Unpinned analysis
# ---------------------------------------------------------------------------


class TestAnalyzeUnpinned:
    """Tests for analyze_unpinned."""

    def test_no_version(self):
        reqs = [ManifestRequirement(name="requests", specifier="", line_number=1)]
        unpinned = analyze_unpinned(reqs)
        assert len(unpinned) == 1
        assert unpinned[0].issue == "no_version"
        assert unpinned[0].severity == "high"

    def test_range_specifier(self):
        reqs = [ManifestRequirement(name="django", specifier=">=4.0", line_number=1)]
        unpinned = analyze_unpinned(reqs)
        assert len(unpinned) == 1
        assert unpinned[0].issue == "range_specifier"
        assert unpinned[0].severity == "medium"

    def test_pinned_no_hash(self):
        reqs = [
            ManifestRequirement(
                name="click", specifier="==8.0.0", is_pinned=True, has_hash=False, line_number=1
            )
        ]
        unpinned = analyze_unpinned(reqs)
        assert len(unpinned) == 1
        assert unpinned[0].issue == "no_hash"
        assert unpinned[0].severity == "low"

    def test_pinned_with_hash(self):
        reqs = [
            ManifestRequirement(
                name="click", specifier="==8.0.0", is_pinned=True, has_hash=True, line_number=1
            )
        ]
        unpinned = analyze_unpinned(reqs)
        assert len(unpinned) == 0

    def test_all_unpinned(self):
        reqs = [
            ManifestRequirement(name="requests", specifier="", line_number=1),
            ManifestRequirement(name="django", specifier=">=4.0", line_number=2),
        ]
        unpinned = analyze_unpinned(reqs)
        assert len(unpinned) == 2


# ---------------------------------------------------------------------------
# Drift analysis
# ---------------------------------------------------------------------------


class TestAnalyzeDrift:
    """Tests for analyze_drift."""

    def test_within_range(self):
        reqs = [ManifestRequirement(name="requests", specifier=">=2.0,<3.0")]
        locked = [LockedPackage(name="requests", version="2.28.0")]
        drift = analyze_drift(reqs, locked)
        assert len(drift) == 1
        assert drift[0].is_within_range is True
        assert drift[0].drift_type == "within_range"

    def test_version_mismatch_range(self):
        reqs = [ManifestRequirement(name="requests", specifier=">=2.0,<2.28")]
        locked = [LockedPackage(name="requests", version="2.28.0")]
        drift = analyze_drift(reqs, locked)
        assert len(drift) == 1
        assert drift[0].is_within_range is False

    def test_pinned_matches(self):
        reqs = [ManifestRequirement(name="click", specifier="==8.0.0", is_pinned=True)]
        locked = [LockedPackage(name="click", version="8.0.0")]
        drift = analyze_drift(reqs, locked)
        assert len(drift) == 0

    def test_pinned_mismatch(self):
        reqs = [ManifestRequirement(name="click", specifier="==7.0.0", is_pinned=True)]
        locked = [LockedPackage(name="click", version="8.0.0")]
        drift = analyze_drift(reqs, locked)
        assert len(drift) == 1
        assert drift[0].drift_type == "version_mismatch"

    def test_no_locked_package(self):
        reqs = [ManifestRequirement(name="nonexistent", specifier=">=1.0")]
        locked = [LockedPackage(name="other", version="1.0.0")]
        drift = analyze_drift(reqs, locked)
        assert len(drift) == 0


# ---------------------------------------------------------------------------
# Hash analysis
# ---------------------------------------------------------------------------


class TestAnalyzeHashes:
    """Tests for analyze_hashes."""

    def test_packages_with_hashes(self):
        packages = [LockedPackage(name="click", version="8.0.0", hashes=["sha256:abc"])]
        issues = analyze_hashes(packages)
        assert len(issues) == 0

    def test_packages_without_hashes(self):
        packages = [LockedPackage(name="click", version="8.0.0", hashes=[])]
        issues = analyze_hashes(packages)
        assert len(issues) == 1
        assert issues[0].issue == "no_hashes_at_all"

    def test_editable_skipped(self):
        packages = [LockedPackage(name="my-pkg", version="0.0.0", is_editable=True, hashes=[])]
        issues = analyze_hashes(packages)
        assert len(issues) == 0


# ---------------------------------------------------------------------------
# LockfileReport
# ---------------------------------------------------------------------------


class TestLockfileReport:
    """Tests for LockfileReport model."""

    def test_is_healthy_empty(self):
        report = LockfileReport(path="test.txt", lockfile_type="requirements_txt")
        assert report.is_healthy is True

    def test_is_healthy_with_unpinned(self):
        report = LockfileReport(
            path="test.txt",
            lockfile_type="requirements_txt",
            unpinned=[UnpinnedDependency(name="x", issue="no_version", severity="high")],
        )
        assert report.is_healthy is False

    def test_to_dict(self):
        report = LockfileReport(path="test.txt", lockfile_type="requirements_txt", total_packages=5)
        d = report.to_dict()
        assert d["path"] == "test.txt"
        assert d["total_packages"] == 5
        assert d["is_healthy"] is True

    def test_severity_counts(self):
        report = LockfileReport(
            path="test.txt",
            lockfile_type="requirements_txt",
            unpinned=[
                UnpinnedDependency(name="a", issue="no_version", severity="high"),
                UnpinnedDependency(name="b", issue="range_specifier", severity="medium"),
                UnpinnedDependency(name="c", issue="no_version", severity="high"),
            ],
        )
        assert report.high_severity_count == 2
        assert report.medium_severity_count == 1


# ---------------------------------------------------------------------------
# UnpinnedDependency
# ---------------------------------------------------------------------------


class TestUnpinnedDependency:
    """Tests for UnpinnedDependency model."""

    def test_to_dict(self):
        u = UnpinnedDependency(
            name="requests",
            issue="no_version",
            severity="high",
            recommendation="Pin requests==X.Y.Z",
        )
        d = u.to_dict()
        assert d["name"] == "requests"
        assert d["issue"] == "no_version"
        assert d["severity"] == "high"

    def test_current_version(self):
        u = UnpinnedDependency(
            name="requests",
            issue="range_specifier",
            severity="medium",
            current_version="2.28.0",
            specifier=">=2.0",
        )
        d = u.to_dict()
        assert d["current_version"] == "2.28.0"
        assert d["specifier"] == ">=2.0"


# ---------------------------------------------------------------------------
# LockedPackage
# ---------------------------------------------------------------------------


class TestLockedPackage:
    """Tests for LockedPackage model."""

    def test_to_dict(self):
        p = LockedPackage(name="click", version="8.0.0", source="pypi", hashes=["sha256:abc"])
        d = p.to_dict()
        assert d["name"] == "click"
        assert d["version"] == "8.0.0"
        assert d["source"] == "pypi"
        assert len(d["hashes"]) == 1

    def test_direct_flag(self):
        p = LockedPackage(name="requests", version="2.28.0", is_direct=True)
        d = p.to_dict()
        assert d["is_direct"] is True


# ---------------------------------------------------------------------------
# Lockfile diff
# ---------------------------------------------------------------------------


class TestLockfileDiff:
    """Tests for LockfileDiff."""

    def test_has_changes_empty(self):
        diff = LockfileDiff(old_path="a", new_path="b")
        assert diff.has_changes is False

    def test_has_changes_added(self):
        diff = LockfileDiff(
            old_path="a",
            new_path="b",
            added=[LockedPackage(name="new", version="1.0.0")],
        )
        assert diff.has_changes is True

    def test_to_dict(self):
        old = LockedPackage(name="click", version="7.0.0")
        new = LockedPackage(name="click", version="8.0.0")
        diff = LockfileDiff(
            old_path="old.txt",
            new_path="new.txt",
            added=[LockedPackage(name="new-pkg", version="1.0.0")],
            removed=[LockedPackage(name="old-pkg", version="0.1.0")],
            changed=[(old, new)],
            unchanged_count=5,
        )
        d = diff.to_dict()
        assert d["old_path"] == "old.txt"
        assert len(d["added"]) == 1
        assert len(d["removed"]) == 1
        assert len(d["changed"]) == 1
        assert d["unchanged_count"] == 5


class TestDiffLockfiles:
    """Tests for diff_lockfiles."""

    def test_identical_files(self, tmp_path):
        content = "click==8.0.0\nrich==13.0.0\n"
        old = tmp_path / "old.txt"
        new = tmp_path / "new.txt"
        old.write_text(content)
        new.write_text(content)
        diff = diff_lockfiles(old, new)
        assert not diff.has_changes
        assert diff.unchanged_count == 2

    def test_added_package(self, tmp_path):
        old = tmp_path / "old.txt"
        new = tmp_path / "new.txt"
        old.write_text("click==8.0.0\n")
        new.write_text("click==8.0.0\nrich==13.0.0\n")
        diff = diff_lockfiles(old, new)
        assert len(diff.added) == 1
        assert diff.added[0].name == "rich"

    def test_removed_package(self, tmp_path):
        old = tmp_path / "old.txt"
        new = tmp_path / "new.txt"
        old.write_text("click==8.0.0\nrich==13.0.0\n")
        new.write_text("click==8.0.0\n")
        diff = diff_lockfiles(old, new)
        assert len(diff.removed) == 1
        assert diff.removed[0].name == "rich"

    def test_changed_version(self, tmp_path):
        old = tmp_path / "old.txt"
        new = tmp_path / "new.txt"
        old.write_text("click==7.0.0\n")
        new.write_text("click==8.0.0\n")
        diff = diff_lockfiles(old, new)
        assert len(diff.changed) == 1
        assert diff.changed[0][0].version == "7.0.0"
        assert diff.changed[0][1].version == "8.0.0"


# ---------------------------------------------------------------------------
# Find lockfiles
# ---------------------------------------------------------------------------


class TestFindLockfiles:
    """Tests for find_lockfiles."""

    def test_find_requirements_txt(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("click==8.0.0\n")
        lockfiles = find_lockfiles(tmp_path)
        names = [f.name for f in lockfiles]
        assert "requirements.txt" in names

    def test_find_pipfile_lock(self, tmp_path):
        (tmp_path / "Pipfile.lock").write_text("{}")
        lockfiles = find_lockfiles(tmp_path)
        names = [f.name for f in lockfiles]
        assert "Pipfile.lock" in names

    def test_find_poetry_lock(self, tmp_path):
        (tmp_path / "poetry.lock").write_text('[[package]]\nname = "x"\nversion = "1.0"\n')
        lockfiles = find_lockfiles(tmp_path)
        names = [f.name for f in lockfiles]
        assert "poetry.lock" in names

    def test_no_lockfiles(self, tmp_path):
        (tmp_path / "README.md").write_text("# Hello")
        lockfiles = find_lockfiles(tmp_path)
        assert len(lockfiles) == 0

    def test_find_multiple(self, tmp_path):
        (tmp_path / "requirements.txt").write_text("click==8.0.0\n")
        (tmp_path / "requirements-dev.txt").write_text("pytest==7.0.0\n")
        lockfiles = find_lockfiles(tmp_path)
        assert len(lockfiles) >= 2


# ---------------------------------------------------------------------------
# Analyze lockfile (integration)
# ---------------------------------------------------------------------------


class TestAnalyzeLockfile:
    """Tests for analyze_lockfile."""

    def test_requirements_txt_analysis(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("click==8.0.0\nrequests>=2.0\n")
        report = analyze_lockfile(req)
        assert report.lockfile_type == "requirements_txt"
        assert report.total_packages >= 1
        # "requests>=2.0" should be flagged as unpinned
        assert any(u.name == "requests" for u in report.unpinned)

    def test_unknown_lockfile_type(self, tmp_path):
        f = tmp_path / "random.txt"
        f.write_text("not a lockfile at all")
        report = analyze_lockfile(f)
        assert len(report.errors) > 0

    def test_pipfile_lock_analysis(self, tmp_path):
        pf = tmp_path / "Pipfile.lock"
        pf.write_text(
            json.dumps(
                {
                    "default": {
                        "requests": {"version": "==2.28.0", "hashes": ["sha256:abc"]},
                    },
                }
            )
        )
        report = analyze_lockfile(pf)
        assert report.lockfile_type == "pipfile_lock"
        assert report.total_packages == 1


# ---------------------------------------------------------------------------
# PipAuditResult
# ---------------------------------------------------------------------------


class TestPipAuditResult:
    """Tests for PipAuditResult."""

    def test_to_dict_clean(self):
        result = PipAuditResult(packages_scanned=10, vulnerabilities_found=0)
        d = result.to_dict()
        assert d["packages_scanned"] == 10
        assert d["vulnerabilities_found"] == 0
        assert d["skipped"] is False

    def test_to_dict_skipped(self):
        result = PipAuditResult(skipped=True, error="not installed")
        d = result.to_dict()
        assert d["skipped"] is True
        assert d["error"] == "not installed"

    def test_to_dict_with_vulns(self):
        result = PipAuditResult(
            packages_scanned=5,
            vulnerabilities_found=2,
            vulnerabilities=[
                {"package": {"name": "foo"}, "id": "PYSEC-1", "severity": "high"},
                {"package": {"name": "bar"}, "id": "PYSEC-2", "severity": "critical"},
            ],
        )
        d = result.to_dict()
        assert len(d["vulnerabilities"]) == 2


class TestRunPipAudit:
    """Tests for run_pip_audit (mocked subprocess)."""

    @patch("depcheck.lockfile.subprocess.run")
    def test_pip_audit_not_installed(self, mock_run):
        mock_run.side_effect = FileNotFoundError("pip-audit not found")
        result = run_pip_audit()
        assert result.skipped is True
        assert "not installed" in result.error

    @patch("depcheck.lockfile.subprocess.run")
    def test_pip_audit_clean(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({"packages": [], "dependencies": []}),
        )
        result = run_pip_audit()
        assert result.vulnerabilities_found == 0

    @patch("depcheck.lockfile.subprocess.run")
    def test_pip_audit_timeout(self, mock_run):
        import subprocess

        mock_run.side_effect = subprocess.TimeoutExpired(cmd="pip-audit", timeout=60)
        result = run_pip_audit()
        assert result.skipped is True
        assert "timed out" in result.error


# ---------------------------------------------------------------------------
# Rendering smoke tests
# ---------------------------------------------------------------------------


class TestLockfileRendering:
    """Smoke tests for lockfile rendering functions."""

    def test_render_table_healthy(self):
        from io import StringIO

        from rich.console import Console

        report = LockfileReport(
            path="requirements.txt",
            lockfile_type="requirements_txt",
            total_packages=3,
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_lockfile_table([report], console=console)
        output = buf.getvalue()
        assert "requirements.txt" in output

    def test_render_table_unhealthy(self):
        from io import StringIO

        from rich.console import Console

        report = LockfileReport(
            path="requirements.txt",
            lockfile_type="requirements_txt",
            total_packages=1,
            unpinned=[
                UnpinnedDependency(
                    name="requests",
                    issue="no_version",
                    severity="high",
                    recommendation="Pin requests==X.Y.Z",
                ),
            ],
        )
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_lockfile_table([report], console=console)
        output = buf.getvalue()
        assert "requests" in output

    def test_render_json(self):
        from io import StringIO

        from rich.console import Console

        report = LockfileReport(path="test.txt", lockfile_type="requirements_txt", total_packages=5)
        buf = StringIO()
        console = Console(file=buf, force_terminal=False, no_color=True)
        render_lockfile_json([report], console=console)
        output = buf.getvalue()
        data = json.loads(output)
        assert len(data) == 1
        assert data[0]["total_packages"] == 5


# ---------------------------------------------------------------------------
# DriftEntry and HashMismatch model tests
# ---------------------------------------------------------------------------


class TestDriftEntry:
    """Tests for DriftEntry model."""

    def test_to_dict(self):
        d = DriftEntry(
            name="pkg",
            manifest_specifier=">=1.0",
            locked_version="1.5.0",
            drift_type="within_range",
            is_within_range=True,
        )
        result = d.to_dict()
        assert result["name"] == "pkg"
        assert result["is_within_range"] is True


class TestHashMismatch:
    """Tests for HashMismatch model."""

    def test_to_dict(self):
        h = HashMismatch(
            name="pkg",
            version="1.0",
            expected_hash="sha256:abc",
            algorithm="sha256",
            issue="no_hashes_at_all",
        )
        result = h.to_dict()
        assert result["issue"] == "no_hashes_at_all"
