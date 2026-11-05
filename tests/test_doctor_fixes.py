"""Tests for depcheck.doctor.apply_fixes automatic fixes."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from depcheck.doctor import (
    Category,
    DoctorReport,
    Finding,
    Severity,
    apply_fixes,
)


def _unpinned_finding(package: str, file_path: Path, line_number: int) -> Finding:
    return Finding(
        category=Category.SECURITY,
        severity=Severity.CRITICAL,
        title="Unpinned requirement in requirements.txt",
        description=f"{package} is not pinned",
        package=package,
        file_path=str(file_path),
        line_number=line_number,
        fix=f"Pin with: {package}==X.Y.Z",
    )


def _patch_pypi(latest_version):
    """Patch depcheck.doctor.PyPIClient so its context manager exposes
    a client whose get_latest_version returns latest_version."""
    mock_cls = patch("depcheck.doctor.PyPIClient").start()
    client = MagicMock()
    client.get_latest_version.side_effect = latest_version
    mock_cls.return_value.__enter__.return_value = client
    return mock_cls


def test_apply_fixes_pins_unpinned_requirement(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")

    report = DoctorReport(project_path=str(tmp_path))
    report.findings.append(_unpinned_finding("requests", req, 1))

    _patch_pypi(lambda package: "2.34.2")
    try:
        results = apply_fixes(report, tmp_path, dry_run=False)
    finally:
        patch.stopall()

    applied = [r for r in results if r["status"] == "applied"]
    assert len(applied) == 1
    assert applied[0]["package"] == "requests"
    assert applied[0]["version"] == "2.34.2"
    assert applied[0]["file"] == str(req)
    assert applied[0]["line"] == 1
    assert req.read_text() == "requests==2.34.2\n"


def test_apply_fixes_preserves_extras_and_indent(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("    requests[security]\n")

    report = DoctorReport(project_path=str(tmp_path))
    report.findings.append(_unpinned_finding("requests", req, 1))

    _patch_pypi(lambda package: "2.34.2")
    try:
        apply_fixes(report, tmp_path, dry_run=False)
    finally:
        patch.stopall()

    assert req.read_text() == "    requests[security]==2.34.2\n"


def test_apply_fixes_dry_run_does_not_write(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")

    report = DoctorReport(project_path=str(tmp_path))
    report.findings.append(_unpinned_finding("requests", req, 1))

    _patch_pypi(lambda package: "2.34.2")
    try:
        results = apply_fixes(report, tmp_path, dry_run=True)
    finally:
        patch.stopall()

    assert req.read_text() == "requests\n"
    assert all(r["status"] == "would_apply" for r in results)


def test_apply_fixes_pypi_lookup_failure_marks_failed(tmp_path: Path) -> None:
    req = tmp_path / "requirements.txt"
    req.write_text("requests\n")

    report = DoctorReport(project_path=str(tmp_path))
    report.findings.append(_unpinned_finding("requests", req, 1))

    _patch_pypi(lambda package: (_ for _ in ()).throw(Exception("network down")))
    try:
        results = apply_fixes(report, tmp_path, dry_run=False)
    finally:
        patch.stopall()

    failed = [r for r in results if r["status"] == "failed"]
    assert len(failed) == 1
    assert req.read_text() == "requests\n"


def test_apply_fixes_no_applicable_findings(tmp_path: Path) -> None:
    report = DoctorReport(project_path=str(tmp_path))
    assert apply_fixes(report, tmp_path) == []
